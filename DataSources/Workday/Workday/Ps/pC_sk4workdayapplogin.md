#### Parser Content
```Java
{
Name = sk4-workday-app-login
  DataType = "app-login"
  Conditions = [ """"successful":true""", """"signonDateTime":""", """workday""", """"authenticationChannel":"""]
  Fields = ${WorkdayParserTemplates.sk4-workday-login-template.Fields}[]

sk4-workday-login-template = {
    Vendor = Workday
    Product =  Workday
    Lms = Splunk
    TimeFormat = "epoch"
    Fields = [
      """exabeam_host=({host}[\w.\-]{1,2000})""",
      """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
      """destinationServiceName =({app}[^ ]{1,2000})""",
      """msg=({additional_info}[^=]{1,2000}?)\s\w+=.""",
      """"signonIPAddress":"({src_ip}[A-Fa-f.\d:]{1,2000})""",
      """"userName":"({user}[^"]{1,2000})""",
      """"{1,20}authenticationType"{1,20}:"{1,20}({auth_method}[^"]{1,2000})"{1,20}""",
      """"authenticationChannel"{1,20}:"{1,20}({auth_method}[^"]{1,2000})""",
      """"signonDateTime"{1,20}:({time}\d{1,100})""",
      """([^\|]{0,2000}\|){5}({activity}[^\|]{1,2000})""",
      """\Wdproc=(|({dproc}[^=]{1,2000}?))(\s{1,100}\w+=|\s{0,100}$)""",
    
}
```