#### Parser Content
```Java
{
Name = xml-4825
    Vendor = Microsoft
    Product = Windows
    Lms = Splunk
    DataType = "windows-failed-logon"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSSSSZ"
    Conditions = ["""<EventID>4825</EventID>""", """<Provider>Microsoft Windows security auditing.</Provider>""", """<Message>A user was denied the access to Remote Desktop."""]
    Fields = [
      """TimeCreated SystemTime(\\)?='({time}\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100}\.\d{9})Z""",
      """<Computer>({host}({dest_host}[\w\-\.]{1,2000})[^<]{0,2000})</Computer>""", 
      """<EventID>({event_code}\d{1,100})</EventID>""",
      """<Data Name(\\)?='AccountName'>(?=\w)?(-|({user}[^<]{1,2000}))<\/Data>""",
      """<Data Name(\\)?='AccountDomain'>(-|({domain}[^<]{1,2000}))<\/Data>""",
      """<Data Name(\\)?='LogonID'>({logon_id}\w{1,100})<\/Data>""",
      """<Data Name(\\)?='ClientAddress'>({src_ip}[a-fA-F0-9\.:]{1,100})<\/Data>""",
      """<Message>({event_name}A user was denied the access to Remote Desktop).""",
    ]
  

}
```