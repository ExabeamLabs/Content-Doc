#### Parser Content
```Java
{
Name = xml-1310
 Vendor = Microsoft
 Product = Microsoft Windows
 Lms = Direct
 DataType = "failed-logon"
 TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSSSSZ"
 Conditions = [ """<EventID Qualifiers='16640'>1310<""", """Failed NTLM Authentication"""]
 Fields = [
   """<Provider Name='({provider_name}[^']{1,2000})""",
   """<EventID Qualifiers='16640'>({event_code}[^<]{1,2000})""",
   """<Keywords>({outcome}[^<]{1,2000})""",
   """<TimeCreated SystemTime='({time}.+?)'""",
   """<EventRecordID>({record_id}[^<]{1,2000})""",
   """<Computer>({host}[^<]{1,2000})""",
   """status=([^:]{1,2000}:)({result_code}[^:]{1,2000}):"""
   """Failed NTLM Authentication for user:\s{1,100}'({domain}[^\\]{1,2000})\\({user}[^']{1,2000})""",
   """<Message>({event_name}.+?)\s{0,100}<"""
   """status=([^:]{1,2000}:){2}({failure_reason}.+?)\s<"""
   ]
   DupFields = ["host->dest_host"]
}
```