// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2002 Roman Zippel <zippel@linux-m68k.org>
 */

#include "images.h"

const char * const xpm_load[] = {
"22 22 5 1",
". c None",
"# c #000000",
"c c #838100",
"a c #ffff00",
"b c #ffffff",
"......................",
"......................",
"......................",
"............####....#.",
"...........#....##.##.",
"..................###.",
".................####.",
".####...........#####.",
"#abab##########.......",
"#babababababab#.......",
"#ababababababa#.......",
"#babababababab#.......",
"#ababab###############",
"#babab##cccccccccccc##",
"#abab##cccccccccccc##.",
"#bab##cccccccccccc##..",
"#ab##cccccccccccc##...",
"#b##cccccccccccc##....",
"###cccccccccccc##.....",
"##cccccccccccc##......",
"###############.......",
"......................"};

const char * const xpm_save[] = {
"22 22 5 1",
". c None",
"# c #000000",
"a c #838100",
"b c #c5c2c5",
"c c #cdb6d5",
"......................",
".####################.",
".#aa#bbbbbbbbbbbb#bb#.",
".#aa#bbbbbbbbbbbb#bb#.",
".#aa#bbbbbbbbbcbb####.",
".#aa#bbbccbbbbbbb#aa#.",
".#aa#bbbccbbbbbbb#aa#.",
".#aa#bbbbbbbbbbbb#aa#.",
".#aa#bbbbbbbbbbbb#aa#.",
".#aa#bbbbbbbbbbbb#aa#.",
".#aa#bbbbbbbbbbbb#aa#.",
".#aaa############aaa#.",
".#aaaaaaaaaaaaaaaaaa#.",
".#aaaaaaaaaaaaaaaaaa#.",
".#aaa#############aa#.",
".#aaa#########bbb#aa#.",
".#aaa#########bbb#aa#.",
".#aaa#########bbb#aa#.",
".#aaa#########bbb#aa#.",
".#aaa#########bbb#aa#.",
"..##################..",
"......................"};

const char * const xpm_back[] = {
"22 22 3 1",
". c None",
"# c #000083",
"a c #838183",
"......................",
"......................",
"......................",
"......................",
"......................",
"...........######a....",
"..#......##########...",
"..##...####......##a..",
"..###.###.........##..",
"..######..........##..",
"..#####...........##..",
"..######..........##..",
"..#######.........##..",
"..########.......##a..",
"...............a###...",
"...............###....",
"......................",
"......................",
"......................",
"......................",
"......................",
"......................"};

const char * const xpm_tree_view[] = {
"22 22 2 1",
". c None",
"# c #000000",
"......................",
"......................",
"......#...............",
"......#...............",
"......#...............",
"......#...............",
"......#...............",
"......########........",
"......#...............",
"......#...............",
"......#...............",
"......#...............",
"......#...............",
"......########........",
"......#...............",
"......#...............",
"......#...............",
"......#...............",
"......#...............",
"......########........",
"......................",
"......................"};

const char * const xpm_single_view[] = {
"22 22 2 1",
". c None",
"# c #000000",
"......................",
"......................",
"..........#...........",
"..........#...........",
"..........#...........",
"..........#...........",
"..........#...........",
"..........#...........",
"..........#...........",
"..........#...........",
"..........#...........",
"..........#...........",
"..........#...........",
"..........#...........",
"..........#...........",
"..........#...........",
"..........#...........",
"..........#...........",
"..........#...........",
"..........#...........",
"......................",
"......................"};

const char * const xpm_split_view[] = {
"22 22 2 1",
". c None",
"# c #000000",
"......................",
"......................",
"......#......#........",
"......#......#........",
"......#......#........",
"......#......#........",
"......#......#........",
"......#......#........",
"......#......#........",
"......#......#........",
"......#......#........",
"......#......#........",
"......#......#........",
"......#......#........",
"......#......#........",
"......#......#........",
"......#......#........",
"......#......#........",
"......#......#........",
"......#......#........",
"......................",
"......................"};

const char * const xpm_symbol_no[] = {
"12 12 2 1",
"  c white",
". c black",
"            ",
" .......... ",
" .        . ",
" .        . ",
" .        . ",
" .        . ",
" .        . ",
" .        . ",
" .        . ",
" .        . ",
" .......... ",
"            "};

const char * const xpm_symbol_mod[] = {
"12 12 2 1",
"  c white",
". c black",
"            ",
" .......... ",
" .        . ",
" .        . ",
" .   ..   . ",
" .  ....  . ",
" .  ....  . ",
" .   ..   . ",
" .        . ",
" .        . ",
" .......... ",
"            "};

const char * const xpm_symbol_yes[] = {
"12 12 2 1",
"  c white",
". c black",
"            ",
" .......... ",
" .        . ",
" .        . ",
" .      . . ",
" .     .. . ",
" . .  ..  . ",
" . ....   . ",
" .  ..    . ",
" .        . ",
" .......... ",
"            "};

const char * const xpm_choice_no[] = {
"12 12 2 1",
"  c white",
". c black",
"            ",
"    ....    ",
"  ..    ..  ",
"  .      .  ",
" .        . ",
" .        . ",
" .        . ",
" .        . ",
"  .      .  ",
"  ..    ..  ",
"    ....    ",
"            "};

const char * const xpm_choice_yes[] = {
"12 12 2 1",
"  c white",
". c black",
"            ",
"    ....    ",
"  ..    ..  ",
"  .      .  ",
" .   ..   . ",
" .  ....  . ",
" .  ....  . ",
" .   ..   . ",
"  .      .  ",
"  ..    ..  ",
"    ....    ",
"            "};

const char * const xpm_menu[] = {
"12 12 2 1",
"  c white",
". c black",
"            ",
" .......... ",
" .        . ",
" . ..     . ",
" . ....   . ",
" . ...... . ",
" . ...... . ",
" . ....   . ",
" . ..     . ",
" .        . ",
" .......... ",
"            "};

const char * const xpm_menu_inv[] = {
"12 12 2 1",
"  c white",
". c black",
"            ",
" .......... ",
" .......... ",
" ..  ...... ",
" ..    .... ",
" ..      .. ",
" ..      .. ",
" ..    .... ",
" ..  ...... ",
" .......... ",
" .......... ",
"            "};

const char * const xpm_menuback[] = {
"12 12 2 1",
"  c white",
". c black",
"            ",
" .......... ",
" .        . ",
" .     .. . ",
" .   .... . ",
" . ...... . ",
" . ...... . ",
" .   .... . ",
" .     .. . ",
" .        . ",
" .......... ",
"            "};

const char * const xpm_void[] = {
"12 12 2 1",
"  c white",
". c black",
"            ",
"            ",
"            ",
"            ",
"            ",
"            ",
"            ",
"            ",
"            ",
"            ",
"            ",
"            "};
