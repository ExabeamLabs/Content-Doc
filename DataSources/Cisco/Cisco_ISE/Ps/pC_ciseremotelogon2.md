#### Parser Content
```Java
{
Name = cise-remote-logon-2
  DataType = "remote-logon"
  Conditions = [ """CISE_Administrative_and_Operational_Audit""" , """ 61025 """, """Open secure connection with TLS peer""" ]
  Fields = ${CiscoParsersTemplates.cise-auth-template.Fields}[
    """({event_code}61025)\s{1,100}({alert_severity}[^\s]{1,2000})\s({activity}[^:]{1,2000}):\s{1,100}({event_name}[^,]{1,2000})""",
    """ISEServiceName =({service_name}[^,]{1,2000})""",
    """ConnectionStatus=({outcome}[^,]{1,2000})""",
    """PeerName =CN=({src_host}[^,]{1,2000})""",
    """FailureReason=({failure_reason}[^,]{1,2000})"""
  ]

cise-auth-template {
  Vendor = Cisco
  Product = Cisco ISE
  Lms = Splunk
  TimeFormat = "yyyy-MM-dd HH:mm:ss.SSS Z"
  Fields = [
    """\d\d:\d\d:\d\d\s({host}[^\s]{1,2000}) CISE_""",
    """({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d\.\d\d\d (-|\+)\d\d:\d\d)""",
    """(?:client IP|AdminIPAddress)(?::|=)\s{0,100}({src_ip}[A-Za-z\d.:]{1,2000})""",
    """(?:UserName|AdminName)=(?:USERNAME|({user_email}[^@,]{1,2000}@[^,]{1,2000})|(?:(?:(?i)host|({domain}[^\\\/,]{1,2000}))[\\\/]{1,2000})?({user}[^,\s]{1,2000}))""",
    """OperationMessageText=({additional_info}[^,]{1,2000})""",
    """AdminInterface=({admin_interface}[^,]{1,2000})"""
  
}
```