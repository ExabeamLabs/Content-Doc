#### Parser Content
```Java
{
Name = mcafee-usb-insert
  Conditions = [ """<DeviceSN>""", """<EventID>20500</EventID>""" ]

mcafee-usb-insert = {
    Vendor = McAfee
    Product = McAfee Endpoint Security
    Lms = Direct
    DataType = "usb-activity"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
    Fields = [
      """<GMTTime>({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
      """exabeam_host=({host}[^\s]{1,2000})""",
      """<MachineName>({src_host}[^<]{1,2000})""",
      """<IPAddress>(::1|({src_ip}[^<]{1,2000}))""",
      """<OSName>({os}[^<]{1,2000})""",
      """<DomainName>({domain}[^<]{1,2000})""",
      """<UserName>(({domain}[^\\]{1,2000})\\+)?({user}[^<]{1,2000})<\/UserName>""",
      """<EventID>({event_code}\d{1,100})""",
      """<DeviceSN>({device_id}[^<]{1,2000})""",
      """<SyncFolder>({file_parent}[^<]{1,2000})"""
    
}
```