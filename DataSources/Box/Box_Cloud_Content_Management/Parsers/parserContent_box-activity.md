#### Parser Content
```Java
{
box-activity = {
  Vendor = Dropbox
  Product = Dropbox
  Lms = Splunk
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
  Fields = [
    """exabeam_host=({host}[\w.\-]+)""",
    """\w+\s{1,100}\d{1,100}\s{1,100}\d\d:\d\d:\d\d ({host}[\w\-.]+) \d{1,100} \d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ""",
    """"timestamp":"({time}[^"]+)""",
    """"host_name":"({host}[^"]+)""",
    """"actor":[^\}]*?"display_name":\s{0,100}"(?:N\/A|({user_fullname}[^"@]+))"""",
    """"actor":[^\}]*?"email":\s{0,100}"(?:N\/A|({user_email}[^@"\s]+@[^@"\s]+))"""",
    """"event_type":(\{"\.tag":)?\s{0,100}"({activity}[^"]+)"""",
    """"description":\s{0,100}"({additional_info}[^"]+)"""",
    """"ip_address":\s{0,100}"({src_ip}(\d{1,3}\.){3}\d{1,3}|([A-Fa-f0-9%.]*:[A-Fa-f0-9%.:]+))""",
    """({app}Dropbox)""",
  ]
}
```