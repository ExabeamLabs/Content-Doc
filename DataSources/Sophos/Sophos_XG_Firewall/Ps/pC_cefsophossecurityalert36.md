#### Parser Content
```Java
{
Name = cef-sophos-security-alert-36
  DataType = "security-alert"
  Conditions = [ """|sophos|sophos central|""", """|Event::Endpoint::Application::Blocked|""", """|Controlled application blocked:""", """group=APPLICATION_CONTROL""" ]
}
cef-sophos-dlp-alert = {
  Vendor = Sophos
  Product = Sophos Endpoint Protection
  Lms = ArcSight
  DataType = "dlp-alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}[^\s]{1,2000})""",
    """\Wrt=({time}\d\d\d\d\-\d\d\-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)""",
    """CEF:([^\|]{0,2000}\|){4}({alert_type}[^\|]{1,2000})""",
    """CEF:([^\|]{0,2000}\|){5}({alert_name}[^:.\|]{1,2000})(:\s({target}[^\|]{1,2000}))?""",
    """CEF:([^\|]{0,2000}\|){5}({additional_info}[^\|]{1,2000})""",
    """CEF:([^\|]{0,2000}\|){5}({alert_name}[^:.\|]{1,2000}).+?Username:\s{0,100}(({domain}[^\\]{1,2000})\\+)?({user}[^\s\\]{1,2000})\s{1,100}Rule names:\s{0,100}′({rule}[^′]{1,2000}).+?Data Control action:\s{0,100}({outcome}[^\s]{1,2000})\s{1,100}File type:\s{0,100}({file_type}.+?)\s{1,100}File size:\s{0,100}({bytes}\d{1,100})\s{1,100}({additional_info}.+?Destination path:\s{0,100}({target}.+?)\s{1,100}Destination type:[^\|]{0,2000})""",
    """CEF:([^\|]{0,2000}\|){6}({alert_severity}[^\|]{1,2000})""",
    """\Wdhost=({src_host}[\w\-.]{1,2000})\s{1,100}(\w+=|$)""",
    """\Wsuser=((({dest_host}[^\s\\]{1,2000})\\+)({user}[^\s\\]{1,2000})|(n\/a|({user_fullname}[^\\]{1,2000}?)))\s{1,100}(\w+=|$)""",
    """\Wid=({alert_id}[^\s]{1,2000})""",
  ]}
```