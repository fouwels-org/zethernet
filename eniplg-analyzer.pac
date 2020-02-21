refine flow ENIPLG_Flow += {
	function enip_header(header: ENIP_Header): bool 
	%{
		//printf("[EVENT: enip_header] "); 
		//printf("com: %#04x ses_handle: %#08x stat: %#08x s_cont: %#016lx opt: %#08x len: %i", ${header.command}, ${header.session_handle}, ${header.status}, ${header.sender_context}, ${header.options}, ${header.length}); 
		//printf("\n");

		BifEvent::generate_eniplg_header(connection()->bro_analyzer(), connection()->bro_analyzer()->Conn(), {header});
		return true;
	%}
	function enip_nop(header: ENIP_Header, body: Nop): bool 
	%{
		printf("[EVENT: enip_nop]"); 
		printf("com: %#04x ses_handle: %#08x stat: %#08x s_cont: %#016lx opt: %#08x len: %i", ${header.command}, ${header.session_handle}, ${header.status}, ${header.sender_context}, ${header.options}, ${header.length}); 
		printf("\n"); 

		BifEvent::generate_eniplg_nop(connection()->bro_analyzer(), connection()->bro_analyzer()->Conn(), {header}, {body});
		return true;
	%}
	function enip_list_services_request(header: ENIP_Header, body: List_Services_Request): bool 
	%{
		printf("[EVENT: enip_list_services_request] ");
		printf("com: %#04x ses_handle: %#08x stat: %#08x s_cont: %#016lx opt: %#08x len: %i", ${header.command}, ${header.session_handle}, ${header.status}, ${header.sender_context}, ${header.options}, ${header.length}); 
		printf("\n");

		BifEvent::generate_list_services_request(connection()->bro_analyzer(), connection()->bro_analyzer()->Conn(), {header}, {body}); 
		return true;
	%}	
	function enip_list_services_response(header: ENIP_Header, body: List_Services_Response): bool 
	%{
		printf("[EVENT: enip_list_services_response] ");
		printf("com: %#04x ses_handle: %#08x stat: %#08x s_cont: %#016lx opt: %#08x len: %i", ${header.command}, ${header.session_handle}, ${header.status}, ${header.sender_context}, ${header.options}, ${header.length}); 
		printf("\n"); 

		BifEvent::generate_eniplg_list_services_response(connection()->bro_analyzer(), connection()->bro_analyzer()->Conn(), {header}, {body}); 
		return true;
	%}	
	function enip_list_identity_request(header: ENIP_Header, body: List_Identity_Request): bool 
	%{
		printf("[EVENT: enip_list_identity_request] ");
		printf("com: %#04x ses_handle: %#08x stat: %#08x s_cont: %#016lx opt: %#08x len: %i", ${header.command}, ${header.session_handle}, ${header.status}, ${header.sender_context}, ${header.options}, ${header.length}); 
		printf("\n");

		BifEvent::generate_eniplg_list_identity_request(connection()->bro_analyzer(), connection()->bro_analyzer()->Conn(), {header}, {body}); 
		return true;
	%}
	function enip_list_identity_response(header: ENIP_Header, body: List_Identity_Response): bool 
	%{
		printf("[EVENT: enip_list_identity_response] ");
		printf("com: %#04x ses_handle: %#08x stat: %#08x s_cont: %#016lx opt: %#08x len: %i serial_number: %#08x: product_name_length: %i product_name: %s", ${header.command}, ${header.session_handle}, ${header.status}, ${header.sender_context}, ${header.options}, ${header.length}, ${body.serial_number}, ${body.product_name_len}, bytestring_to_string(${body.product_name})); 
		printf("\n"); 

		BifEvent::generate_eniplg_list_identity_response(connection()->bro_analyzer(), connection()->bro_analyzer()->Conn(), {header}, {body}); 
		return true;


		//printf("[EVENT: enip_list_identity] Vendor %#02x Product %s\n", ${body.vendor}, std_str(${body.product_name}).c_str());
	 	//BifEvent::generate_eniplg_identity(connection()->bro_analyzer(), connection()->bro_analyzer()->Conn(), ${body.vendor}, ${body.product_name});
	%}
	function enip_list_interfaces_request(header: ENIP_Header, body: List_Interfaces_Request): bool 
	%{
		printf("[EVENT: enip_list_interfaces_request] ");
		printf("com: %#04x ses_handle: %#08x stat: %#08x s_cont: %#016lx opt: %#08x len: %i", ${header.command}, ${header.session_handle}, ${header.status}, ${header.sender_context}, ${header.options}, ${header.length}); 
		printf("\n"); 

		BifEvent::generate_eniplg_list_interfaces_request((connection()->bro_analyzer(), connection()->bro_analyzer()->Conn(), {header}, {body}); 
		return true;
	%}	
	function enip_list_interfaces_response(header: ENIP_Header, body: List_Interfaces_Response): bool 
	%{
		printf("[EVENT: enip_list_interfaces_response] ");
		printf("com: %#04x ses_handle: %#08x stat: %#08x s_cont: %#016lx opt: %#08x len: %i", ${header.command}, ${header.session_handle}, ${header.status}, ${header.sender_context}, ${header.options}, ${header.length}); 
		printf("\n"); 

		BifEvent::generate_eniplg_list_interfaces_response(connection()->bro_analyzer(), connection()->bro_analyzer()->Conn(), {header}, {body}); 
		return true;
	%}	
	function enip_register_session_request(header: ENIP_Header, body: Register_Session_Request): bool 
	%{
		printf("[EVENT: enip_register_session_request] ");
		printf("com: %#04x ses_handle: %#08x stat: %#08x s_cont: %#016lx opt: %#08x len: %i proto_ver: %#04x opt_flags: %#04x", ${header.command}, ${header.session_handle}, ${header.status}, ${header.sender_context}, ${header.options}, ${header.length}, ${body.protocol_version}, ${body.options_flags});  
		printf("\n"); 

		BifEvent::generate_eniplg_register_session_request(connection()->bro_analyzer(), connection()->bro_analyzer()->Conn(), {header}, {body}); 
		return true;
	%}	
	function enip_register_session_response(header: ENIP_Header, body: Register_Session_Response): bool 
	%{
		printf("[EVENT: enip_register_session_response] ");
		printf("com: %#04x ses_handle: %#08x stat: %#08x s_cont: %#016lx opt: %#08x len: %i proto_ver: %#04x opt_flags: %#04x", ${header.command}, ${header.session_handle}, ${header.status}, ${header.sender_context}, ${header.options}, ${header.length}, ${body.protocol_version}, ${body.options_flags});  
		printf("\n"); 

		BifEvent::generate_eniplg_register_session_response(connection()->bro_analyzer(), connection()->bro_analyzer()->Conn(), {header}, {body}); 
		return true;
	%}	
	function enip_unregister_session(header: ENIP_Header, body: UnRegister_Session): bool 
	%{
		printf("[EVENT: enip_unregister_session] ");
		printf("com: %#04x ses_handle: %#08x stat: %#08x s_cont: %#016lx opt: %#08x len: %i", ${header.command}, ${header.session_handle}, ${header.status}, ${header.sender_context}, ${header.options}, ${header.length}); 
		printf("\n"); 

		BifEvent::generate_eniplg_unregister_session(connection()->bro_analyzer(), connection()->bro_analyzer()->Conn(), {header}, {body}); 
		return true;
	%}	
	function enip_sendrr_data(header: ENIP_Header, body: Send_RR_Data): bool 
	%{
		printf("[EVENT: enip_sendrr_data] ");
		printf("com: %#04x ses_handle: %#08x stat: %#08x s_cont: %#016lx opt: %#08x len: %i int_handle: %#08x timeout: %i", ${header.command}, ${header.session_handle}, ${header.status}, ${header.sender_context}, ${header.options}, ${header.length}, ${body.InterfaceHandle}, ${body.Timeout}); 
		printf("\n");

		BifEvent::generate_eniplg_sendrr_data(connection()->bro_analyzer(), connection()->bro_analyzer()->Conn(), {header}, {body});  
		return true;
	%}	
	function enip_send_unit_data(header: ENIP_Header, body: Send_Unit_Data): bool 
	%{
		printf("[EVENT: enip_send_unit_data] ");
		printf("com: %#04x ses_handle: %#08x stat: %#08x s_cont: %#016lx opt: %#08x len: %i int_handle: %#08x timeout: %i", ${header.command}, ${header.session_handle}, ${header.status}, ${header.sender_context}, ${header.options}, ${header.length}, ${body.InterfaceHandle}, ${body.Timeout}); 
		printf("\n"); 

		BifEvent::generate_eniplg_send_unit_data(connection()->bro_analyzer(), connection()->bro_analyzer()->Conn(), {header}, {body}); 
		return true;
	%}	
};

