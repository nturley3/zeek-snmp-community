##! Zeek script is used to detect usage of default community strings.

@load base/frameworks/notice

module SNMP;

export {
        redef enum Notice::Type += {
                Default_Community_String
        };
}

const snmp_strings = /public*/ | /private*/ &redef;

event snmp_get_request(c: connection, is_orig: bool, header: SNMP::Header, pdu: SNMP::PDU)
{
        if (c$snmp?$community &&
            snmp_strings in c$snmp$community &&
            Site::is_local_addr(c$id$orig_h) &&
            Site::is_local_addr(c$id$resp_h))
            {
                NOTICE([$note=SNMP::Default_Community_Strings,
                $conn=c,
                $msg=fmt("%s is communicating with default SNMP community strings (%s) with %s.", c$id$orig_h, c$snmp$community, c$id$resp_h),
                $sub=fmt("%s", c$snmp$community),
                $identifier=cat(c$id$resp_h),
                $suppress_for=1day]);
            }
}
