#### Parser Content
```Java
{
Name = raw-4662-3
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "object-access"
  TimeFormat = "epoch"
  Conditions = [ """CEF:0|""", """|Microsoft-Windows-Security-Auditing:4662|""", """An operation was performed on an object""" ]
  Fields = [
    """exabeam_host=([^=]+?@\s{0,100})?({host}[\w.-]+)""",
    """({event_name}An operation was performed on an object)""",
    """({event_code}4662)""",
    """\srt=({time}\d{1,100})""",
    """ahost=({host}[^\s]+)""",
    """\sdhost=({dest_host}[^\s]+)""",
    """\sdntdom=(-|({domain}[^\s]+))""",
    """duser=(-|({user}[^\s]+))""",
    """\sduid=({logon_id}[^\s]+)""",
    """agt=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",	
    """originalAgentAddress=({src_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})""",	
    """amac=({src_mac}[^\s]+)""",
    """originalAgentMacAddress=({src_mac}[^\s]+)""",
    """cs5=({object}[^\s]+)""",
    """ad\.Object:Object_,?Server=({object_class}[^=]+?)\s{0,100}([^=\s]+=|$)""",
    """ad\.Operation:Operation_,?Type=({activity}[^=]+?)\s{0,100}([^=\s]+=|$)""",
  ]
}
```