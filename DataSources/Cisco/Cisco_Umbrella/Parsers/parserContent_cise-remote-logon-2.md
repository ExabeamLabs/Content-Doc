#### Parser Content
```Java
{
Name = cise-remote-logon-2
  DataType = "remote-logon"
  Conditions = [ """CISE_Administrative_and_Operational_Audit""" , """ 61025 """, """Open secure connection with TLS peer""" ]
  Fields = ${CiscoParsersTemplates.cise-auth-template.Fields}[
    """({event_code}61025)\s{1,100}({alert_severity}[^\s]{1,2000})\s({activity}[^:]{1,2000}):\s{1,100}({event_name}[^,]{1,2000})""",
    """ISEServiceName=({service_name}[^,]{1,2000})""",
    """ConnectionStatus=({outcome}[^,]{1,2000})""",
    """PeerName=CN=({src_host}[^,]{1,2000})""",
    """FailureReason=({failure_reason}[^,]{1,2000})"""
  ]
}
```