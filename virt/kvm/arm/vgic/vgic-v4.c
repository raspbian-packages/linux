// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2017 ARM Ltd.
 * Author: Marc Zyngier <marc.zyngier@arm.com>
 */

#include <linux/interrupt.h>
#include <linux/irq.h>
#include <linux/irqdomain.h>
#include <linux/kvm_host.h>
#include <linux/irqchip/arm-gic-v3.h>

#include "vgic.h"

/*
 * How KVM uses GICv4 (insert rude comments here):
 *
 * The vgic-v4 layer acts as a bridge between several entities:
 * - The GICv4 ITS representation offered by the ITS driver
 * - VFIO, which is in charge of the PCI endpoint
 * - The virtual ITS, which is the only thing the guest sees
 *
 * The configuration of VLPIs is triggered by a callback from VFIO,
 * instructing KVM that a PCI device has been configured to deliver
 * MSIs to a vITS.
 *
 * kvm_vgic_v4_set_forwarding() is thus called with the routing entry,
 * and this is used to find the corresponding vITS data structures
 * (ITS instance, device, event and irq) using a process that is
 * extremely similar to the injection of an MSI.
 *
 * At this stage, we can link the guest's view of an LPI (uniquely
 * identified by the routing entry) and the host irq, using the GICv4
 * driver mapping operation. Should the mapping succeed, we've then
 * successfully upgraded the guest's LPI to a VLPI. We can then start
 * with updating GICv4's view of the property table and generating an
 * INValidation in order to kickstart the delivery of this VLPI to the
 * guest directly, without software intervention. Well, almost.
 *
 * When the PCI endpoint is deconfigured, this operation is reversed
 * with VFIO calling kvm_vgic_v4_unset_forwarding().
 *
 * Once the VLPI has been mapped, it needs to follow any change the
 * guest performs on its LPI through the vITS. For that, a number of
 * command handlers have hooks to communicate these changes to the HW:
 * - Any invalidation triggers a call to its_prop_update_vlpi()
 * - The INT command results in a irq_set_irqchip_state(), which
 *   generates an INT on the corresponding VLPI.
 * - The CLEAR command results in a irq_set_irqchip_state(), which
 *   generates an CLEAR on the corresponding VLPI.
 * - DISCARD translates into an unmap, similar to a call to
 *   kvm_vgic_v4_unset_forwarding().
 * - MOVI is translated by an update of the existing mapping, changing
 *   the target vcpu, resulting in a VMOVI being generated.
 * - MOVALL is translated by a string of mapping updates (similar to
 *   the handling of MOVI). MOVALL is horrible.
 *
 * Note that a DISCARD/MAPTI sequence emitted from the guest without
 * reprogramming the PCI endpoint after MAPTI does not result in a
 * VLPI being mapped, as there is no callback from VFIO (the guest
 * will get the interrupt via the normal SW injection). Fixing this is
 * not trivial, and requires some horrible messing with the VFIO
 * internals. Not fun. Don't do that.
 *
 * Then there is the scheduling. Each time a vcpu is about to run on a
 * physical CPU, KVM must tell the corresponding redistributor about
 * it. And if we've migrated our vcpu from one CPU to another, we must
 * tell the ITS (so that the messages reach the right redistributor).
 * This is done in two steps: first issue a irq_set_affinity() on the
 * irq corresponding to the vcpu, then call its_schedule_vpe(). You
 * must be in a non-preemptible context. On exit, another call to
 * its_schedule_vpe() tells the redistributor that we're done with the
 * vcpu.
 *
 * Finally, the doorbell handling: Each vcpu is allocated an interrupt
 * which will fire each time a VLPI is made pending whilst the vcpu is
 * not running. Each time the vcpu gets blocked, the doorbell
 * interrupt gets enabled. When the vcpu is unblocked (for whatever
 * reason), the doorbell interrupt is disabled.
 */

#define DB_IRQ_FLAGS	(IRQ_NOAUTOEN | IRQ_DISABLE_UNLAZY | IRQ_NO_BALANCING)

static irqreturn_t vgic_v4_doorbell_handler(int irq, void *info)
{
	struct kvm_vcpu *vcpu = info;

	/* We got the message, no need to fire again */
	if (!irqd_irq_disabled(&irq_to_desc(irq)->irq_data))
		disable_irq_nosync(irq);

	vcpu->arch.vgic_cpu.vgic_v3.its_vpe.pending_last = true;
	kvm_make_request(KVM_REQ_IRQ_PENDING, vcpu);
	kvm_vcpu_kick(vcpu);

	return IRQ_HANDLED;
}

/**
 * vgic_v4_init - Initialize the GICv4 data structures
 * @kvm:	Pointer to the VM being initialized
 *
 * We may be called each time a vITS is created, or when the
 * vgic is initialized. This relies on kvm->lock to be
 * held. In both cases, the number of vcpus should now be
 * fixed.
 */
int vgic_v4_init(struct kvm *kvm)
{
	struct vgic_dist *dist = &kvm->arch.vgic;
	struct kvm_vcpu *vcpu;
	int i, nr_vcpus, ret;

	if (!kvm_vgic_global_state.has_gicv4)
		return 0; /* Nothing to see here... move along. */

	if (dist->its_vm.vpes)
		return 0;

	nr_vcpus = atomic_read(&kvm->online_vcpus);

	dist->its_vm.vpes = kcalloc(nr_vcpus, sizeof(*dist->its_vm.vpes),
				    GFP_KERNEL);
	if (!dist->its_vm.vpes)
		return -ENOMEM;

	dist->its_vm.nr_vpes = nr_vcpus;

	kvm_for_each_vcpu(i, vcpu, kvm)
		dist->its_vm.vpes[i] = &vcpu->arch.vgic_cpu.vgic_v3.its_vpe;

	ret = its_alloc_vcpu_irqs(&dist->its_vm);
	if (ret < 0) {
		kvm_err("VPE IRQ allocation failure\n");
		kfree(dist->its_vm.vpes);
		dist->its_vm.nr_vpes = 0;
		dist->its_vm.vpes = NULL;
		return ret;
	}

	kvm_for_each_vcpu(i, vcpu, kvm) {
		int irq = dist->its_vm.vpes[i]->irq;

		/*
		 * Don't automatically enable the doorbell, as we're
		 * flipping it back and forth when the vcpu gets
		 * blocked. Also disable the lazy disabling, as the
		 * doorbell could kick us out of the guest too
		 * early...
		 */
		irq_set_status_flags(irq, DB_IRQ_FLAGS);
		ret = request_irq(irq, vgic_v4_doorbell_handler,
				  0, "vcpu", vcpu);
		if (ret) {
			kvm_err("failed to allocate vcpu IRQ%d\n", irq);
			/*
			 * Trick: adjust the number of vpes so we know
			 * how many to nuke on teardown...
			 */
			dist->its_vm.nr_vpes = i;
			break;
		}
	}

	if (ret)
		vgic_v4_teardown(kvm);

	return ret;
}

/**
 * vgic_v4_teardown - Free the GICv4 data structures
 * @kvm:	Pointer to the VM being destroyed
 *
 * Relies on kvm->lock to be held.
 */
void vgic_v4_teardown(struct kvm *kvm)
{
	struct its_vm *its_vm = &kvm->arch.vgic.its_vm;
	int i;

	if (!its_vm->vpes)
		return;

	for (i = 0; i < its_vm->nr_vpes; i++) {
		struct kvm_vcpu *vcpu = kvm_get_vcpu(kvm, i);
		int irq = its_vm->vpes[i]->irq;

		irq_clear_status_flags(irq, DB_IRQ_FLAGS);
		free_irq(irq, vcpu);
	}

	its_free_vcpu_irqs(its_vm);
	kfree(its_vm->vpes);
	its_vm->nr_vpes = 0;
	its_vm->vpes = NULL;
}

int vgic_v4_put(struct kvm_vcpu *vcpu, bool need_db)
{
	struct its_vpe *vpe = &vcpu->arch.vgic_cpu.vgic_v3.its_vpe;
	struct irq_desc *desc = irq_to_desc(vpe->irq);

	if (!vgic_supports_direct_msis(vcpu->kvm) || !vpe->resident)
		return 0;

	/*
	 * If blocking, a doorbell is required. Undo the nested
	 * disable_irq() calls...
	 */
	while (need_db && irqd_irq_disabled(&desc->irq_data))
		enable_irq(vpe->irq);

	return its_schedule_vpe(vpe, false);
}

int vgic_v4_load(struct kvm_vcpu *vcpu)
{
	struct its_vpe *vpe = &vcpu->arch.vgic_cpu.vgic_v3.its_vpe;
	int err;

	if (!vgic_supports_direct_msis(vcpu->kvm) || vpe->resident)
		return 0;

	/*
	 * Before making the VPE resident, make sure the redistributor
	 * corresponding to our current CPU expects us here. See the
	 * doc in drivers/irqchip/irq-gic-v4.c to understand how this
	 * turns into a VMOVP command at the ITS level.
	 */
	err = irq_set_affinity(vpe->irq, cpumask_of(smp_processor_id()));
	if (err)
		return err;

	/* Disabled the doorbell, as we're about to enter the guest */
	disable_irq_nosync(vpe->irq);

	err = its_schedule_vpe(vpe, true);
	if (err)
		return err;

	/*
	 * Now that the VPE is resident, let's get rid of a potential
	 * doorbell interrupt that would still be pending.
	 */
	return irq_set_irqchip_state(vpe->irq, IRQCHIP_STATE_PENDING, false);
}

static struct vgic_its *vgic_get_its(struct kvm *kvm,
				     struct kvm_kernel_irq_routing_entry *irq_entry)
{
	struct kvm_msi msi  = (struct kvm_msi) {
		.address_lo	= irq_entry->msi.address_lo,
		.address_hi	= irq_entry->msi.address_hi,
		.data		= irq_entry->msi.data,
		.flags		= irq_entry->msi.flags,
		.devid		= irq_entry->msi.devid,
	};

	return vgic_msi_to_its(kvm, &msi);
}

int kvm_vgic_v4_set_forwarding(struct kvm *kvm, int virq,
			       struct kvm_kernel_irq_routing_entry *irq_entry)
{
	struct vgic_its *its;
	struct vgic_irq *irq;
	struct its_vlpi_map map;
	int ret;

	if (!vgic_supports_direct_msis(kvm))
		return 0;

	/*
	 * Get the ITS, and escape early on error (not a valid
	 * doorbell for any of our vITSs).
	 */
	its = vgic_get_its(kvm, irq_entry);
	if (IS_ERR(its))
		return 0;

	mutex_lock(&its->its_lock);

	/* Perform the actual DevID/EventID -> LPI translation. */
	ret = vgic_its_resolve_lpi(kvm, its, irq_entry->msi.devid,
				   irq_entry->msi.data, &irq);
	if (ret)
		goto out;

	/*
	 * Emit the mapping request. If it fails, the ITS probably
	 * isn't v4 compatible, so let's silently bail out. Holding
	 * the ITS lock should ensure that nothing can modify the
	 * target vcpu.
	 */
	map = (struct its_vlpi_map) {
		.vm		= &kvm->arch.vgic.its_vm,
		.vpe		= &irq->target_vcpu->arch.vgic_cpu.vgic_v3.its_vpe,
		.vintid		= irq->intid,
		.properties	= ((irq->priority & 0xfc) |
				   (irq->enabled ? LPI_PROP_ENABLED : 0) |
				   LPI_PROP_GROUP1),
		.db_enabled	= true,
	};

	ret = its_map_vlpi(virq, &map);
	if (ret)
		goto out;

	irq->hw		= true;
	irq->host_irq	= virq;
	atomic_inc(&map.vpe->vlpi_count);

out:
	mutex_unlock(&its->its_lock);
	return ret;
}

int kvm_vgic_v4_unset_forwarding(struct kvm *kvm, int virq,
				 struct kvm_kernel_irq_routing_entry *irq_entry)
{
	struct vgic_its *its;
	struct vgic_irq *irq;
	int ret;

	if (!vgic_supports_direct_msis(kvm))
		return 0;

	/*
	 * Get the ITS, and escape early on error (not a valid
	 * doorbell for any of our vITSs).
	 */
	its = vgic_get_its(kvm, irq_entry);
	if (IS_ERR(its))
		return 0;

	mutex_lock(&its->its_lock);

	ret = vgic_its_resolve_lpi(kvm, its, irq_entry->msi.devid,
				   irq_entry->msi.data, &irq);
	if (ret)
		goto out;

	WARN_ON(!(irq->hw && irq->host_irq == virq));
	if (irq->hw) {
		atomic_dec(&irq->target_vcpu->arch.vgic_cpu.vgic_v3.its_vpe.vlpi_count);
		irq->hw = false;
		ret = its_unmap_vlpi(virq);
	}

out:
	mutex_unlock(&its->its_lock);
	return ret;
}
