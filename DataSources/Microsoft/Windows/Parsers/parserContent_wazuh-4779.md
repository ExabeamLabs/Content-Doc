#### Parser Content
```Java
{
Name = wazuh-4779
  DataType = "windows-4779"
  Conditions = [ """"data.id":"4779"""", """"type":"wazuh-alerts"""", """"decoder.parent":"windows""""  ]
  Fields = ${WazuhParserTemplates.wazuh-windows-template.Fields} [
    """({event_name}A session was disconnected from a Window Station)""",
    """Account Name:\s*({user}\S+)\s+Account Domain:""",
    """Account Domain:\s*({domain}\S+)\s+Logon ID:""",
    """Logon ID:\s*({logon_id}\S+)""",
    """Service Name:\s*({dest_host}.+?)\s*Service ID""",
    """Client Address:\s*(::[\w]+:)?({src_ip}[a-fA-F:\d.]+)""",  
  ]
}
```