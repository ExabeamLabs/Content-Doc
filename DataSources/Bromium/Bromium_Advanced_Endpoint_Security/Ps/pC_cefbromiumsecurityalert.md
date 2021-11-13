#### Parser Content
```Java
{
Name = cef-bromium-security-alert
  Conditions = [ """|Bromium, Inc.|vSentry|""", """suser=""", """vSentry blocked an unauthorized """ ]

cef-bromium-security-alert = {
    Vendor = Bromium
    Product = Bromium Advanced Endpoint Security
    Lms = Splunk
    DataType = "alert"
    TimeFormat = "yyyy-MM-dd HH:mm:ss.SSSZ"
    Fields = [
      """\Wrt=({time}\w+\s{1,100}\d{1,100}\s{1,100}\d{1,100}:\d{1,100}:\d{1,100})""",
      """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d\.\d\d\d-\d{1,100})""",
      """\s({host}[\w\-.]{1,2000})\sCEF:\d{1,100}\|Bromium, Inc.\|""",
      """^([^|]{0,2000}\|){5}({alert_name}[^|]{1,2000})""",
      """^([^|]{0,2000}\|){6}({alert_severity}[^|]{1,2000})""",
      """\Wshost=({src_host}.+?)\s{0,100}(\w+=|$)""",
      """\Wsuser=({user}[^@=]{1,2000}?)\s{0,100}(\w+=|$)""",
      """\Wsuser=({user_email}[^@=]{1,2000}?@[^@=]{1,2000}?)\s{0,100}(\w+=|$)""",
      """\Wsrc=({src_ip}[a-fA-F\d.:]{1,2000})""",
      """\Wcs1=({malware_url}.+?)\s{0,100}(\w+=|$)""",
      """\Wmsg=({additional_info}.+?)\s{0,100}(\w+=|$)"""
      """\Wsproc=({process}.*?)\s{0,100}\w+=""",
    ]
    DupFields = [ "alert_name->alert_type" 
}
```