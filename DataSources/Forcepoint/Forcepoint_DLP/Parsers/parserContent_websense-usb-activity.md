#### Parser Content
```Java
{
Name = websense-usb-activity
  Vendor = Forcepoint
  Product = Forcepoint DLP
  Lms = Direct
  DataType = "usb-activity"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ "CEF:","|Websense|Data Security", "sourceServiceName=Endpoint Removable Media", "act=Permitted" ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """exabeam_host=({host}[^\s]+)""",
    """\ssuser=({user}.+?)\s{1,100}(\w+=|$)""",
    """\sloginName=(({domain}[^\\]+)\\+)?({user}.+?)\s{1,100}(\w+=|$)""",
    """\sfname=(N\/A|({file_path}.*?[\/\\]+[^\\\/]+))\s{1,100}\- [\d.]+ """,
    """\sfname=(N\/A|.*?[\/\\]+({file_name}[^\\\/]+))\s{1,100}\- [\d.]+ """,
    """\smsg=({activity}.+?)\s{1,100}(\w+=|$)""",
    """\scat=({activity_details}.+?)\s{1,100}(\w+=|$)""",
    """\sfname=(N\/A|.*?[\/\\]+[^\\\/]+ - ({bytes_num}[\d.]+)\s{1,100}({bytes_unit}[^\s;]+))""",
    """\sduser=(?:|({device_id}.+?))\s{1,100}(\w+=|$)""",
    """({device_type}(USB|DVD|Removable Media))"""
  ]
}
```