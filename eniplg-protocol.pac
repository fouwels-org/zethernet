# Generated by binpac_quickstart

# ## TODO: Add your protocol structures in here.
# ## some examples:

# Types are your basic building blocks.
# There are some builtins, or you can define your own.
# Here's a definition for a regular expression:
# type ENIPLG_WHITESPACE = RE/[ \t]*/;

# A record is a collection of types.
# Here's one with the built-in types
# type example = record {
# 	
# };


enum command_codes {
    NOP                 = 0x0000,
    LIST_SERVICES       = 0x0004,
    LIST_IDENTITY       = 0x0063,
    LIST_INTERFACES     = 0x0064,
    REGISTER_SESSION    = 0x0065,
    UNREGISTER_SESSION  = 0x0066,
    SEND_RR_DATA        = 0x006F,
    SEND_UNIT_DATA      = 0x0070,
    INDICATE_STATUS     = 0x0072,
    CANCEL              = 0x0073,
    # Other values are Reserved for future usage or Reserved for legacy
    };


type ENIPLG_PDU(is_orig: bool) = case is_orig of {
    true  -> request    : ENIP_Request;
    false -> response   : ENIP_Response;
    } &byteorder=littleendian;

# switch for the request portion
type ENIP_Request = record {
    header  : ENIP;
    data    : case(header.command) of {
                ##NOP                     -> nop                  : Nop;
            	##REGISTER_SESSION        -> register_session     : Register;
                ##! UNREGISTER_SESSION  -> unregister_session   : Register;
                ##SEND_RR_DATA            -> send_rr_data         : RR_Unit(header);
                ##SEND_UNIT_DATA          -> send_unit_data       : RR_Unit(header);
                default                 -> unknown              : bytestring &restofdata;
                };
    } &byteorder=littleendian;

# switch for the response portion
type ENIP_Response = record {
    header: ENIP;
    data: case(header.command) of {
        #LIST_SERVICES       -> list_services        : List_Services;
        LIST_IDENTITY       -> list_identity        : List_Identity;
        #LIST_INTERFACES     -> list_interfaces      : List_Interfaces;
        #REGISTER_SESSION    -> register_session     : Register;
        #UNREGISTER_SESSION  -> unregister_session   : Register;
        #SEND_RR_DATA        -> send_rr_data         : RR_Unit(header);
        ##! SEND_UNIT_DATA  -> send_unit_data       : RR_Unit(header);
        default             -> unknown              : bytestring &restofdata;
        };
    } &byteorder=littleendian;

type ENIP = record {
    command         : uint16;               # Command identifier
    length          : uint16;               # Length of everyting (header + data)
    session_handle  : uint32;               # Session handle
    status          : uint32;               # Status
    sender_context  : bytestring &length=8; # Sender context
    options         : uint32;               # Option flags
    } &byteorder=littleendian;

type List_Identity = record {
    item_count          : uint16;
    response_id         : uint16;
    length              : uint16;
    encap_version       : uint16;
    sock_info           : Sock_Info;
    vendor              : uint16;
    device_type         : uint16;
    product_code        : uint16;
    revision_high       : uint8;
    revision_low        : uint8;
    status              : uint16;
    serial_number       : uint32;
    product_name_len    : uint8;
    product_name        : bytestring &length=product_name_len;
    state               : uint8;
    } &byteorder=littleendian, &let {
        proc: bool = $context.flow.enip_list_identity(this);
    };


type Sock_Info = record {
    sin_family  : int16;
    sin_port    : uint16;
    sin_addr    : uint32;
    sin_zero    : uint8[8];
    } &byteorder=bigendian;