# SPDX-FileCopyrightText: 2020 Kaelan Thijs Fouwels <kaelan.thijs@fouwels.com>
#
# SPDX-License-Identifier: MIT

refine flow ENIPLG_Flow += {
	function header(header: Header): bool 
	%{
		BifEvent::generate_eniplg_header(connection()->bro_analyzer(), connection()->bro_analyzer()->Conn(), 
		${header.command}, 
		${header.length}, 
		${header.session_handle}, 
		${header.status}, 
		${header.sender_context}, 
		${header.options}
		);
		return true;
	%}
	function nop(header: Header, body: Nop): bool 
	%{
		BifEvent::generate_eniplg_nop(connection()->bro_analyzer(), connection()->bro_analyzer()->Conn()
		);
		return true;
	%}
	function list_services_request(header: Header, body: List_Services_Request): bool 
	%{
		BifEvent::generate_eniplg_list_services_request(connection()->bro_analyzer(), connection()->bro_analyzer()->Conn()
		);
		return true;
	%}	
	function list_services_response(header: Header, body: List_Services_Response): bool 
	%{
		BifEvent::generate_eniplg_list_services_response(connection()->bro_analyzer(), connection()->bro_analyzer()->Conn(),
		${body.item_count}
		);
		return true;
	%}	
	function list_identity_request(header: Header, body: List_Identity_Request): bool 
	%{
		BifEvent::generate_eniplg_list_identity_request(connection()->bro_analyzer(), connection()->bro_analyzer()->Conn()
		); 
		return true;
	%}
	function list_identity_response(header: Header, body: List_Identity_Response): bool 
	%{
		BifEvent::generate_eniplg_list_identity_response(connection()->bro_analyzer(), connection()->bro_analyzer()->Conn(),
		${body.item_count},
		${body.type_id},
		${body.encap_version},
		${body.sock_info.sin_family},
		${body.sock_info.sin_port},
		${body.sock_info.sin_addr},
		${body.vendor},
		${body.device_type},
		${body.product_code},
		${body.revision},
		${body.status},
		${body.serial_number},
		bytestring_to_val(${body.product_name}),
		${body.state}
		); 
		return true;
	%}
	function list_interfaces_request(header: Header, body: List_Interfaces_Request): bool 
	%{
		BifEvent::generate_eniplg_list_interfaces_request(connection()->bro_analyzer(), connection()->bro_analyzer()->Conn()
		);
		return true;
	%}
	function list_interfaces_response(header: Header, body: List_Interfaces_Response): bool 
	%{
		BifEvent::generate_eniplg_list_interfaces_response(connection()->bro_analyzer(), connection()->bro_analyzer()->Conn(),
		${body.item_count}
		);
		return true;
	%}
	function register_session_request(header: Header, body: Register_Session_Request): bool 
	%{
		BifEvent::generate_eniplg_register_session_request(connection()->bro_analyzer(), connection()->bro_analyzer()->Conn(),
		${body.protocol_version},
		${body.options_flags}
		);
		return true;
	%}
	function register_session_response(header: Header, body: Register_Session_Response): bool 
	%{
		BifEvent::generate_eniplg_register_session_response(connection()->bro_analyzer(), connection()->bro_analyzer()->Conn(),
		${body.protocol_version},
		${body.options_flags}
		);
		return true;
	%}
	function unregister_session(header: Header, body: UnRegister_Session): bool 
	%{
		BifEvent::generate_eniplg_unregister_session(connection()->bro_analyzer(), connection()->bro_analyzer()->Conn()
		);
		return true;
	%}
	function send_rr_data(header: Header, body: Send_RR_Data): bool 
	%{
		BifEvent::generate_eniplg_send_rr_data(connection()->bro_analyzer(), connection()->bro_analyzer()->Conn(),
		${body.interface_handle},
		${body.timeout}
		);
		return true;
	%}
	function send_unit_data(header: Header, body: Send_Unit_Data): bool 
	%{
		BifEvent::generate_eniplg_send_unit_data(connection()->bro_analyzer(), connection()->bro_analyzer()->Conn(),
		${body.interface_handle},
		${body.timeout}
		);
		return true;
	%}
	function indicate_status_request(header: Header, body: Indicate_Status_Request): bool 
	%{
		BifEvent::generate_eniplg_indicate_status_request(connection()->bro_analyzer(), connection()->bro_analyzer()->Conn()
		);
		return true;
	%}
	function indicate_status_response(header: Header, body: Indicate_Status_Response): bool 
	%{
		BifEvent::generate_eniplg_indicate_status_response(connection()->bro_analyzer(), connection()->bro_analyzer()->Conn()
		);
		return true;
	%}
	function cancel_request(header: Header, body: Cancel_Request): bool 
	%{
		BifEvent::generate_eniplg_cancel_request(connection()->bro_analyzer(), connection()->bro_analyzer()->Conn()
		);
		return true;
	%}
	function cancel_response(header: Header, body: Cancel_Response): bool 
	%{
		BifEvent::generate_eniplg_cancel_response(connection()->bro_analyzer(), connection()->bro_analyzer()->Conn()
		);
		return true;
	%}
	function unrecognized_request(header: Header, body: Unrecognized_Request): bool 
	%{
		BifEvent::generate_eniplg_unrecognized_request(connection()->bro_analyzer(), connection()->bro_analyzer()->Conn(),
		${header.command}
		);
		return true;
	%}
	function unrecognized_response(header: Header, body: Unrecognized_Response): bool 
	%{
		BifEvent::generate_eniplg_unrecognized_response(connection()->bro_analyzer(), connection()->bro_analyzer()->Conn(),
		${header.command}
		);
		return true;
	%}
};