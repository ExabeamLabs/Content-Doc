#### Parser Content
```Java
{
Name = cef-dropbox-app-activity-1
  Conditions = [ """CEF:""", """|Skyformation|SkyFormation Cloud Apps Security|""", """"file_operations"}""" ]
  Fields = ${DropboxParserTemplates.cef-dropbox-activity.Fields}[
    """"assets":\[[^\]]*?"display_name":"({object}[^",]+)"""",
    """"assets":\[[^\]]*?"contextual":"({resource}[^",]+)""""
  ]
}
cef-dropbox-activity = {
  Vendor = Dropbox
  Product = Dropbox
  Lms = Splunk
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
  Fields = [
    """exabeam_host=({host}[\w.\-]+)""",
    """\w+\s+\d+\s+\d\d:\d\d:\d\d ({host}[\w\-.]+) \d+ \d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ""",
    """"timestamp":"({time}[^"]+)""",
    """"host_name":"({host}[^"]+)""",
    """"actor":[^\}]*?"display_name":\s*"(?:N\/A|({user_fullname}[^"@]+))"""",
    """"actor":[^\}]*?"email":\s*"(?:N\/A|({user_email}[^@"\s]+@[^@"\s]+))"""",
    """"event_type":(\{"\.tag":)?\s*"({activity}[^"]+)"""",
    """"description":\s*"({additional_info}[^"]+)"""",
    """"ip_address":\s*"({src_ip}(\d{1,3}\.){3}\d{1,3}|([A-Fa-f0-9%.]*:[A-Fa-f0-9%.:]+))""",
    """({app}Dropbox)""",
  ]

```