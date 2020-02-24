function headerToVal(hdr: Header): BroVal
%{
	RecordVal* r = new RecordVal(BifType::Record::ENIPLG::Header);

	r->Assign(0, val_mgr->GetCount(${hdr.command}));
	r->Assign(1, val_mgr->GetCount(${hdr.length}));
	r->Assign(2, val_mgr->GetCount(${hdr.session_handle}));
	r->Assign(3, val_mgr->GetCount(${hdr.status}));
	r->Assign(4, val_mgr->GetCount(${hdr.sender_context}));
	r->Assign(5, val_mgr->GetCount(${hdr.options}));
	return r;
%}

function list_Identity_ResponseToVal(body: List_Identity_Response): BroVal
%{
	RecordVal* r = new RecordVal(BifType::Record::ENIPLG::List_Identity_Response);
	r->Assign(0, val_mgr->GetCount(${body.item_count}));
	r->Assign(1, val_mgr->GetCount(${body.type_id}));
	r->Assign(2, val_mgr->GetCount(${body.length}));
	r->Assign(3, val_mgr->GetCount(${body.encap_version}));
	r->Assign(4, val_mgr->GetCount(${body.sock_info.sin_family}));
	r->Assign(5, val_mgr->GetCount(${body.sock_info.sin_port}));
	r->Assign(6, val_mgr->GetCount(${body.sock_info.sin_addr}));
	r->Assign(7, val_mgr->GetCount(${body.vendor}));
	r->Assign(8, val_mgr->GetCount(${body.device_type}));
	r->Assign(9, val_mgr->GetCount(${body.product_code}));
	r->Assign(10, val_mgr->GetCount(${body.revision}));
	r->Assign(11, val_mgr->GetCount(${body.status}));
	r->Assign(12, val_mgr->GetCount(${body.serial_number}));
	r->Assign(13, val_mgr->GetCount(${body.product_name_len}));
	r->Assign(14, bytestring_to_val(${body.product_name}));
	r->Assign(15, val_mgr->GetCount(${body.state}));
	return r;
%}

refine flow ENIPLG_Flow += {
	function header(header: Header): bool 
	%{
		BifEvent::generate_eniplg_header(connection()->bro_analyzer(), connection()->bro_analyzer()->Conn(), headerToVal(header));
		return true;
	%}
	function nop(header: Header, body: Nop): bool 
	%{
		BifEvent::generate_eniplg_nop(connection()->bro_analyzer(), connection()->bro_analyzer()->Conn(), headerToVal(header));
		return true;
	%}
	function list_services_request(header: Header, body: List_Services_Request): bool 
	%{
		BifEvent::generate_eniplg_list_services_request(connection()->bro_analyzer(), connection()->bro_analyzer()->Conn(), headerToVal(header)); 
		return true;
	%}	
	function list_services_response(header: Header, body: List_Services_Response): bool 
	%{
		BifEvent::generate_eniplg_list_services_response(connection()->bro_analyzer(), connection()->bro_analyzer()->Conn(), headerToVal(header)); 
		return true;
	%}	
	function list_identity_request(header: Header, body: List_Identity_Request): bool 
	%{
		
		BifEvent::generate_eniplg_list_identity_request(connection()->bro_analyzer(), connection()->bro_analyzer()->Conn(), headerToVal(header)); 
		return true;
	%}
	function list_identity_response(header: Header, body: List_Identity_Response): bool 
	%{
		BifEvent::generate_eniplg_list_identity_response(connection()->bro_analyzer(), connection()->bro_analyzer()->Conn(), headerToVal(header), list_Identity_ResponseToVal(body)); 
		return true;
	%}
	function list_interfaces_request(header: Header, body: List_Interfaces_Request): bool 
	%{
		BifEvent::generate_eniplg_list_interfaces_request(connection()->bro_analyzer(), connection()->bro_analyzer()->Conn(), headerToVal(header)); 
		return true;
	%}
	function list_interfaces_response(header: Header, body: List_Interfaces_Response): bool 
	%{
		BifEvent::generate_eniplg_list_interfaces_response(connection()->bro_analyzer(), connection()->bro_analyzer()->Conn(), headerToVal(header)); 
		return true;
	%}
	function register_session_request(header: Header, body: Register_Session_Request): bool 
	%{
		BifEvent::generate_eniplg_register_session_request(connection()->bro_analyzer(), connection()->bro_analyzer()->Conn(), headerToVal(header)); 
		return true;
	%}
	function register_session_response(header: Header, body: Register_Session_Response): bool 
	%{
		BifEvent::generate_eniplg_register_session_response(connection()->bro_analyzer(), connection()->bro_analyzer()->Conn(), headerToVal(header)); 
		return true;
	%}
	function unregister_session(header: Header, body: UnRegister_Session): bool 
	%{
		BifEvent::generate_eniplg_unregister_session(connection()->bro_analyzer(), connection()->bro_analyzer()->Conn(), headerToVal(header)); 
		return true;
	%}
	function send_rr_data(header: Header, body: Send_RR_Data): bool 
	%{
		BifEvent::generate_eniplg_send_rr_data(connection()->bro_analyzer(), connection()->bro_analyzer()->Conn(), headerToVal(header));  
		return true;
	%}
	function send_unit_data(header: Header, body: Send_Unit_Data): bool 
	%{
		BifEvent::generate_eniplg_send_unit_data(connection()->bro_analyzer(), connection()->bro_analyzer()->Conn(), headerToVal(header)); 
		return true;
	%}
};