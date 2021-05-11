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
   """<Provider Name='({provider_name}[^']+)""",
   """<EventID Qualifiers='16640'>({event_code}[^<]+)""",
   """<Keywords>({outcome}[^<]+)""",
   """<TimeCreated SystemTime='({time}.+?)'""",
   """<EventRecordID>({record_id}[^<]+)""",
   """<Computer>({host}[^<]+)""",
   """status=([^:]+:)({result_code}[^:]+):"""
   """Failed NTLM Authentication for user:\s{1,100}'({domain}[^\\]+)\\({user}[^']+)""",
   """<Message>({event_name}.+?)\s{0,100}<"""
   """status=([^:]+:){2}({failure_reason}.+?)\s<"""
   ]
   DupFields = ["host->dest_host"]
}
```