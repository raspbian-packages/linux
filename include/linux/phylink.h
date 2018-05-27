#ifndef NETDEV_PCS_H
#define NETDEV_PCS_H

#include <linux/phy.h>
#include <linux/spinlock.h>
#include <linux/workqueue.h>

struct device_node;
struct ethtool_cmd;
struct fwnode_handle;
struct net_device;

enum {
	MLO_PAUSE_NONE,
	MLO_PAUSE_ASYM = BIT(0),
	MLO_PAUSE_SYM = BIT(1),
	MLO_PAUSE_RX = BIT(2),
	MLO_PAUSE_TX = BIT(3),
	MLO_PAUSE_TXRX_MASK = MLO_PAUSE_TX | MLO_PAUSE_RX,
	MLO_PAUSE_AN = BIT(4),

	MLO_AN_PHY = 0,	/* Conventional PHY */
	MLO_AN_FIXED,	/* Fixed-link mode */
	MLO_AN_INBAND,	/* In-band protocol */
};

static inline bool phylink_autoneg_inband(unsigned int mode)
{
	return mode == MLO_AN_INBAND;
}

/**
 * struct phylink_link_state - link state structure
 * @advertising: ethtool bitmask containing advertised link modes
 * @lp_advertising: ethtool bitmask containing link partner advertised link
 *   modes
 * @interface: link &typedef phy_interface_t mode
 * @speed: link speed, one of the SPEED_* constants.
 * @duplex: link duplex mode, one of DUPLEX_* constants.
 * @pause: link pause state, described by MLO_PAUSE_* constants.
 * @link: true if the link is up.
 * @an_enabled: true if autonegotiation is enabled/desired.
 * @an_complete: true if autonegotiation has completed.
 */
struct phylink_link_state {
	__ETHTOOL_DECLARE_LINK_MODE_MASK(advertising);
	__ETHTOOL_DECLARE_LINK_MODE_MASK(lp_advertising);
	phy_interface_t interface;
	int speed;
	int duplex;
	int pause;
	unsigned int link:1;
	unsigned int an_enabled:1;
	unsigned int an_complete:1;
};

/**
 * struct phylink_mac_ops - MAC operations structure.
 * @validate: Validate and update the link configuration.
 * @mac_link_state: Read the current link state from the hardware.
 * @mac_config: configure the MAC for the selected mode and state.
 * @mac_an_restart: restart 802.3z BaseX autonegotiation.
 * @mac_link_down: take the link down.
 * @mac_link_up: allow the link to come up.
 *
 * The individual methods are described more fully below.
 */
struct phylink_mac_ops {
	void (*validate)(struct net_device *ndev, unsigned long *supported,
			 struct phylink_link_state *state);
	int (*mac_link_state)(struct net_device *ndev,
			      struct phylink_link_state *state);
	void (*mac_config)(struct net_device *ndev, unsigned int mode,
			   const struct phylink_link_state *state);
	void (*mac_an_restart)(struct net_device *ndev);
	void (*mac_link_down)(struct net_device *ndev, unsigned int mode);
	void (*mac_link_up)(struct net_device *ndev, unsigned int mode,
			    struct phy_device *phy);
};

#if 0 /* For kernel-doc purposes only. */
/**
 * validate - Validate and update the link configuration
 * @ndev: a pointer to a &struct net_device for the MAC.
 * @supported: ethtool bitmask for supported link modes.
 * @state: a pointer to a &struct phylink_link_state.
 *
 * Clear bits in the @supported and @state->advertising masks that
 * are not supportable by the MAC.
 *
 * Note that the PHY may be able to transform from one connection
 * technology to another, so, eg, don't clear 1000BaseX just
 * because the MAC is unable to BaseX mode. This is more about
 * clearing unsupported speeds and duplex settings.
 *
 * If the @state->interface mode is %PHY_INTERFACE_MODE_1000BASEX
 * or %PHY_INTERFACE_MODE_2500BASEX, select the appropriate mode
 * based on @state->advertising and/or @state->speed and update
 * @state->interface accordingly.
 */
void validate(struct net_device *ndev, unsigned long *supported,
	      struct phylink_link_state *state);

/**
 * mac_link_state() - Read the current link state from the hardware
 * @ndev: a pointer to a &struct net_device for the MAC.
 * @state: a pointer to a &struct phylink_link_state.
 *
 * Read the current link state from the MAC, reporting the current
 * speed in @state->speed, duplex mode in @state->duplex, pause mode
 * in @state->pause using the %MLO_PAUSE_RX and %MLO_PAUSE_TX bits,
 * negotiation completion state in @state->an_complete, and link
 * up state in @state->link.
 */
int mac_link_state(struct net_device *ndev,
		   struct phylink_link_state *state);

/**
 * mac_config() - configure the MAC for the selected mode and state
 * @ndev: a pointer to a &struct net_device for the MAC.
 * @mode: one of %MLO_AN_FIXED, %MLO_AN_PHY, %MLO_AN_INBAND.
 * @state: a pointer to a &struct phylink_link_state.
 *
 * The action performed depends on the currently selected mode:
 *
 * %MLO_AN_FIXED, %MLO_AN_PHY:
 *   Configure the specified @state->speed, @state->duplex and
 *   @state->pause (%MLO_PAUSE_TX / %MLO_PAUSE_RX) mode.
 *
 * %MLO_AN_INBAND:
 *   place the link in an inband negotiation mode (such as 802.3z
 *   1000base-X or Cisco SGMII mode depending on the @state->interface
 *   mode). In both cases, link state management (whether the link
 *   is up or not) is performed by the MAC, and reported via the
 *   mac_link_state() callback. Changes in link state must be made
 *   by calling phylink_mac_change().
 *
 *   If in 802.3z mode, the link speed is fixed, dependent on the
 *   @state->interface. Duplex is negotiated, and pause is advertised
 *   according to @state->an_enabled, @state->pause and
 *   @state->advertising flags. Beware of MACs which only support full
 *   duplex at gigabit and higher speeds.
 *
 *   If in Cisco SGMII mode, the link speed and duplex mode are passed
 *   in the serial bitstream 16-bit configuration word, and the MAC
 *   should be configured to read these bits and acknowledge the
 *   configuration word. Nothing is advertised by the MAC. The MAC is
 *   responsible for reading the configuration word and configuring
 *   itself accordingly.
 */
void mac_config(struct net_device *ndev, unsigned int mode,
		const struct phylink_link_state *state);

/**
 * mac_an_restart() - restart 802.3z BaseX autonegotiation
 * @ndev: a pointer to a &struct net_device for the MAC.
 */
void mac_an_restart(struct net_device *ndev);

/**
 * mac_link_down() - take the link down
 * @ndev: a pointer to a &struct net_device for the MAC.
 * @mode: link autonegotiation mode
 *
 * If @mode is not an in-band negotiation mode (as defined by
 * phylink_autoneg_inband()), force the link down and disable any
 * Energy Efficient Ethernet MAC configuration.
 */
void mac_link_down(struct net_device *ndev, unsigned int mode);

/**
 * mac_link_up() - allow the link to come up
 * @ndev: a pointer to a &struct net_device for the MAC.
 * @mode: link autonegotiation mode
 * @phy: any attached phy
 *
 * If @mode is not an in-band negotiation mode (as defined by
 * phylink_autoneg_inband()), allow the link to come up. If @phy
 * is non-%NULL, configure Energy Efficient Ethernet by calling
 * phy_init_eee() and perform appropriate MAC configuration for EEE.
 */
void mac_link_up(struct net_device *ndev, unsigned int mode,
		 struct phy_device *phy);
#endif

struct phylink *phylink_create(struct net_device *, struct fwnode_handle *,
	phy_interface_t iface, const struct phylink_mac_ops *ops);
void phylink_destroy(struct phylink *);

int phylink_connect_phy(struct phylink *, struct phy_device *);
int phylink_of_phy_connect(struct phylink *, struct device_node *, u32 flags);
void phylink_disconnect_phy(struct phylink *);
int phylink_fixed_state_cb(struct phylink *,
			   void (*cb)(struct net_device *dev,
				      struct phylink_link_state *));

void phylink_mac_change(struct phylink *, bool up);

void phylink_start(struct phylink *);
void phylink_stop(struct phylink *);

void phylink_ethtool_get_wol(struct phylink *, struct ethtool_wolinfo *);
int phylink_ethtool_set_wol(struct phylink *, struct ethtool_wolinfo *);

int phylink_ethtool_ksettings_get(struct phylink *,
				  struct ethtool_link_ksettings *);
int phylink_ethtool_ksettings_set(struct phylink *,
				  const struct ethtool_link_ksettings *);
int phylink_ethtool_nway_reset(struct phylink *);
void phylink_ethtool_get_pauseparam(struct phylink *,
				    struct ethtool_pauseparam *);
int phylink_ethtool_set_pauseparam(struct phylink *,
				   struct ethtool_pauseparam *);
int phylink_ethtool_get_module_info(struct phylink *, struct ethtool_modinfo *);
int phylink_ethtool_get_module_eeprom(struct phylink *,
				      struct ethtool_eeprom *, u8 *);
int phylink_get_eee_err(struct phylink *);
int phylink_ethtool_get_eee(struct phylink *, struct ethtool_eee *);
int phylink_ethtool_set_eee(struct phylink *, struct ethtool_eee *);
int phylink_mii_ioctl(struct phylink *, struct ifreq *, int);

#define phylink_zero(bm) \
	bitmap_zero(bm, __ETHTOOL_LINK_MODE_MASK_NBITS)
#define __phylink_do_bit(op, bm, mode) \
	op(ETHTOOL_LINK_MODE_ ## mode ## _BIT, bm)

#define phylink_set(bm, mode)	__phylink_do_bit(__set_bit, bm, mode)
#define phylink_clear(bm, mode)	__phylink_do_bit(__clear_bit, bm, mode)
#define phylink_test(bm, mode)	__phylink_do_bit(test_bit, bm, mode)

void phylink_set_port_modes(unsigned long *bits);

#endif
