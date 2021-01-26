#### Parser Content
```Java
{
Name = s-owa-activity
    Vendor = Microsoft
    Product = Exchange
    Lms = Splunk
    DataType = "app-activity"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
    Conditions = [ "ISAWebLog", "exabeam_raw" ]
    Fields = [
      """exabeam_host=({host}[\w.\-]+)""",
      """exabeam_raw=.*?({time}[^\s]+)""",
      """ISAWebLog\t[^\t]+\t({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
      """ISAWebLog\t([^\t]+\t){2}\(\w+\)({user}.+?)\t""",
      """ISAWebLog\t([^\t]+\t){6}(?:-|({app}.+?))\t""",
      """ISAWebLog\t([^\t]+\t){12}(?:-|({activity}.+?))\t""",
      """Cmd=({activity}.+?)(\t|&)""",
      """ISAWebLog\t([^\t]+\t){7}({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
      """ISAWebLog\t([^\t]+\t){13}(?:-|({additional_info}.+?))\t""",
      """DeviceType=({src_host}[^&\t]+)"""
      """User=({domain}[^%]+)%5C"""
    ]
  }
```