%include binpac.pac
%include bro.pac

%extern{
	#include "events.bif.h"
%}

analyzer ENIPLG withcontext {
	connection: ENIPLG_Conn;
	flow:       ENIPLG_Flow;
};

connection ENIPLG_Conn(bro_analyzer: BroAnalyzer) {
	upflow   = ENIPLG_Flow(true);
	downflow = ENIPLG_Flow(false);
};

%include eniplg-protocol.pac

flow ENIPLG_Flow(is_orig: bool) {
	datagram = PDU(is_orig) withcontext(connection, this);
};

%include eniplg-analyzer.pac