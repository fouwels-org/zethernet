<!-- 
SPDX-FileCopyrightText: 2020 Kaelan Thijs Fouwels <kaelan.thijs@fouwels.com>

SPDX-License-Identifier: MIT
-->

# Zeek - ENIP

Industrial Ethernet/IP DPI/IDS module for ZEEK, for OT/ICS ENIP event analysis.

Targetting ZEEK v3.X.X

Written in BINPAC, a ZEEK specific DSL..

See `events.bif` for exported handlers, all standard ENIP/IP events are decoded and made available to subscription.

See `scripts/main.zeek` for an example zeek/scripts consumer for all events.

See `Dockerfile` for the three stage compilation/zeek module linking process.

## License
MIT and/or MIT compatible

Licensing tracked via SPDX, see file level tags for specific attribution