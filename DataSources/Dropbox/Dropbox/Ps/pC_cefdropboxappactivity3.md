#### Parser Content
```Java
{
Name = cef-dropbox-app-activity-3
  Conditions = [ """destinationServiceName =Dropbox""", """.tag""", """"access_method"""",  """"sharing"}""" ]
  Fields = ${DropboxParserTemplates.cef-dropbox-activity.Fields}[
    """"assets":\s{0,100}\[[^\]]{0,2000}?"display_name":\s{0,100}"({object}[^",]{1,2000})"""",
  ]

cef-dropbox-activity = {
  Vendor = Dropbox
  Product = Dropbox
  Lms = Splunk
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
  Fields = [
    """exabeam_host=({host}[\w.\-]{1,2000})""",
    """\w+\s{1,100}\d{1,100}\s{1,100}\d\d:\d\d:\d\d ({host}[\w\-.]{1,2000}) \d{1,100} \d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ""",
    """"timestamp":\s{0,100}"({time}[^"]{1,2000})""",
    """"host_name":\s{0,100}"({host}[^"]{1,2000})""",
    """"actor":\s{0,100}[^\}]{0,2000}?"display_name":\s{0,100}"(?:N\/A|({user_fullname}[^"@]{1,2000}))"""",
    """"actor":\s{0,100}[^\}]{0,2000}?"email":\s{0,100}"(?:N\/A|({user_email}[^@"\s]{1,2000}@[^@"\s]{1,2000}))"""",
    """"event_type":\s{0,100}"({activity}[^"]{1,2000})"""",
    """"event_type":\s{0,100}\{("description":\s{0,100}"[^"]+",\s{0,100})?"\.tag":\s{0,100}"({activity}[^"]{1,2000})"""",
    """"description":\s{0,100}"({additional_info}[^"]{1,2000})"""",
    """"ip_address":\s{0,100}"({src_ip}(\d{1,3}\.){3}\d{1,3}|([A-Fa-f0-9%.]{0,2000}:[A-Fa-f0-9%.:]{1,2000}))""",
    """({app}Dropbox)""",
  
}
```