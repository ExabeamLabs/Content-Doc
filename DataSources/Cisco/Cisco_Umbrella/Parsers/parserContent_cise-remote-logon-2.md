#### Parser Content
```Java
{
Name = cise-remote-logon-2
  DataType = "remote-logon"
  Conditions = [ """CISE_Administrative_and_Operational_Audit""" , """ 61025 """, """Open secure connection with TLS peer""" ]
  Fields = ${CiscoParsersTemplates.cise-auth-template.Fields}[
    """({event_code}61025)\s{1,100}({alert_severity}[^\s]+)\s({activity}[^:]+):\s{1,100}({event_name}[^,]+)""",
    """ISEServiceName=({service_name}[^,]+)""",
    """ConnectionStatus=({outcome}[^,]+)""",
    """PeerName=CN=({src_host}[^,]+)""",
    """FailureReason=({failure_reason}[^,]+)"""
  ]
}
```