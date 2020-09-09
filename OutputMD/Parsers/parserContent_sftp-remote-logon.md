#### Parser Content
```Java
{
Name = sftp-remote-logon
  DataType = "remote-logon"
  Conditions = [ """sftp-server[""",""" session opened """]
  Fields = ${UnixParserTemplates.sftp-server-activity.Fields}[
    """user\s({user}.+?)\sfrom\s\[({src_ip}[A-Fa-f:\d.]+)\]""",
    """({event_name}session opened)"""
	]
  }
```