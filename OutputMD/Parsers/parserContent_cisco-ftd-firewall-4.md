#### Parser Content
```Java
{
Name = cisco-ftd-firewall-4
  DataType = "network-connection"
  Conditions = [ """%FTD""", """Pre-allocate SIP NOTIFY""" ]
  Fields = ${CiscoParsersTemplates.cisco-ftd-event-1.Fields}[
    """({event_name}Pre-allocate SIP NOTIFY TCP secondary channel)""",
    """for VPNDECRYPTED:({src_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})\/({src_port}\d+)"""
  ]
}
```