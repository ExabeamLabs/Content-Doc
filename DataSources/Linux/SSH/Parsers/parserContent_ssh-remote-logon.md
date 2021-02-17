#### Parser Content
```Java
{
Name = ssh-remote-logon
  Vendor = Linux
  Product = SSH
  Lms = Splunk
  DataType = "ssh-login"
  TimeFormat = "yyyy-MM-dd HH:mm:ss.S"
  Conditions = [ """SSH_Logon_""", """USER_TEXT: """, """COLLECTORNAME: """, """ ASSET_COLLECTORRID: """, """SVA_IP_ADDRESS: """ ]
  Fields = [
    """EVENT_DT:\s"+({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d\.\d)"""",
    """\sHOSTADDR:\s"+({dest_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})"""",
    """\sHOSTNAME:\s+"+({host}[^"]+)"+\s""",
    """Remote From:\s*({src_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})""",
    """\sDESCRIPTION:\s"+({description}[^"]+)"""",
    """OSTYPE_D:\s"+({os}[^"]+)"+\s""",
    """Session id:\s*({session_id}\d+)""",
    """Process Name:\s*(null|unknown|({process_name}\S+))""",
    """Parent Name:\s*(null|unknown|({parent_process_name}\S+))""",
    """Username:\s*({user}\S+)""",
    """Port:\s*({src_port}\d+)""",
    """\sRULE_NAME: "*({rule_name}[^"]+)"""",
    """EVENT_TYPE_D:\s+"+({event_name}[^"]+)"+\s""",
    """EVENT_ID:\s+"+({logon_id}[^"]+)"+\s""",
    """PROCESS_ID:\s+"+(null|unknown|({pid}[^"]+))"+\s"""
  ]
  DupFields = [ "event_name->event_type" ]
}
```