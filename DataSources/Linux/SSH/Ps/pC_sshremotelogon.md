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
    """EVENT_DT:\s"{1,20}({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d\.\d)"""",
    """\sHOSTADDR:\s"{1,20}({dest_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})"""",
    """\sHOSTNAME:\s{1,100}"{1,20}({host}[^"]{1,2000})"{1,20}\s""",
    """Remote From:\s{0,100}({src_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})""",
    """\sDESCRIPTION:\s"{1,20}({description}[^"]{1,2000})"""",
    """OSTYPE_D:\s"{1,20}({os}[^"]{1,2000})"{1,20}\s""",
    """Session id:\s{0,100}({session_id}\d{1,100})""",
    """Process Name:\s{0,100}(null|unknown|({process_name}\S+))""",
    """Parent Name:\s{0,100}(null|unknown|({parent_process_name}\S+))""",
    """Username:\s{0,100}({user}\S+)""",
    """Port:\s{0,100}({src_port}\d{1,100})""",
    """\sRULE_NAME: "{0,20}({rule_name}[^"]{1,2000})"""",
    """EVENT_TYPE_D:\s{1,100}"{1,20}({event_name}[^"]{1,2000})"{1,20}\s""",
    """EVENT_ID:\s{1,100}"{1,20}({logon_id}[^"]{1,2000})"{1,20}\s""",
    """PROCESS_ID:\s{1,100}"{1,20}(null|unknown|({pid}[^"]{1,2000}))"{1,20}\s"""
  ]
  DupFields = [ "event_name->event_type" ]
}
```