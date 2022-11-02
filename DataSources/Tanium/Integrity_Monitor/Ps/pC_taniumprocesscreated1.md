#### Parser Content
```Java
{
Name = tanium-process-created-1
  DataType = "process-created"
  Conditions = [ """"event":"process_start"""", """"tanium_parent_process_id"""",""""user__name":""" ]

tanium-operations-1 = {
  Vendor = Tanium
  Product = Integrity Monitor
  Lms = Direct
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSZ"
  Fields = [
	""""timestamp":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\d\d\d\d[+-]\d\d:\d\d)"""",
	""""hostname":"({host}[\w\-.]{1,2000})"""",
	""""login__user_name":"({user}[^"]{1,2000})"""",
        """"process__login__user_name":"({user}[^"]{1,2000})"""",
	""""event":"({event_name}[^"]{1,2000})"""",
	""""file__md5":"({md5}[^"]{1,2000})"""",
	""""parent_pid":({pid}\d{1,100})""",
	""""command_line":"({command_line}[^"]{1,2000}?)\s{0,100}"""",
	""""parent__command_line":"({parent_command_line}[^"]{1,2000})\s{0,100}"""",
	""""parent_pid":({parent_process_id}\d{1,100})""",
  
}
```