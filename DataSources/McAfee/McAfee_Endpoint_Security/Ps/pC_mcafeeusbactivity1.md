#### Parser Content
```Java
{
Name = mcafee-usb-activity-1
  Conditions = [ """<DeviceSN>""", """<EventID>20508</EventID>""" ]
}
mcafee-usb-insert = {
    Vendor = McAfee
    Product = McAfee Endpoint Security
    Lms = Direct
    DataType = "usb-activity"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
    Fields = [
      """<GMTTime>({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
      """exabeam_host=({host}[^\s]{1,2000})""",
      """({host}[\w\-.]{1,2000})\s{1,100}EPOEvents""",
      """<MachineName>({dest_host}[\w\-.]{1,2000})""",
      """<IPAddress>({dest_ip}[A-Fa-f:\d.]{1,2000})<""",
      """<OSName>({os}[^<]{1,2000})""",
      """<UserName>({domain}[^\\<]{1,2000})\\+[^<]{1,2000}<""",
      """<UserName>(({domain}[^\\<]{1,2000})\\+)?({user}[^,<]{1,2000})<\/UserName>""",
      """<EventID>({event_code}\d{1,100})""",
      """<DeviceSN>({device_id}[^<]{1,2000})""",
      """<SyncFolder>({file_parent}[^<]{1,2000})""",
      """<Severity>({alert_severity}\d{1,100})"""
    ]}
```