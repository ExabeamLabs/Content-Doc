#### Parser Content
```Java
{
Name = trendmicro-network-conn-failed
  Vendor = Trend Micro
  Product = Deep Security Agent
  Lms = Direct
  DataType = "network-connection-failed"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """\d\d:\d\d\s({host}.+?)\sCEF:""",
    """proto=({protocol}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
    """in=({bytes_in}\d{1,100})""",
    """out=({bytes_out}\d{1,100})""",
    """dst=({dest_ip}[^\s]{1,2000})""",
    """src=({src_ip}[^\s]{1,2000})""",
    """dmac=({dest_mac}[^\s]{1,2000})""",
    """smac=({src_mac}[^\s]{1,2000})""",
    """dvchost=({dest_host}[^\s]{1,2000})""",
    """act=IDS:({activity}[^\s]{1,2000})""",
    """cs2=({method}[^\s]{1,2000})""",
    """CEF.*?\|(.*?\|){4}({rule}.+?)\|"""
    """dpt=({dest_port}\d{1,100})"""
    """spt=({src_port}\d{1,100})"""
    """cs1=({additional_info}.+?)\s\w+=""",
    """suser=(NT AUTHORITY\\+SYSTEM|({user}[^\s]{1,2000}))""",
    """fileHash=({file_hash}[^\s]{1,2000})""",
    """cs3=({md5}[^\s]{1,2000})""",
    """cs2=({sha1}[^\s]{1,2000})""",
    """suid=({suid}.+?)\s\w+=""",
    """filePath=({file_path}({file_parent}[^,]{0,2000}?)[\\\/]{0,2000}({file_name}[^\\]{1,2000}?(\.({file_ext}[^\.\s]{1,2000}))?))\s\w+="""
  ]
  Conditions = [
     """|Trend Micro|Deep Security Agent|""",
     """act=IDS:Deny""",
     """CEF:"""
  ]
  DupFields = ["rule->failure_reason"]


}
```