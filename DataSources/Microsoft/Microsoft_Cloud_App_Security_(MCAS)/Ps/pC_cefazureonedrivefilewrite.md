#### Parser Content
```Java
{
Name = cef-azure-onedrive-file-write
  Vendor = Microsoft
  Product = Microsoft Cloud App Security (MCAS)
  Lms = Splunk
  DataType = "file-write"
  IsHVF = true
  TimeFormat = "epoch"
  Conditions = [ "CEF:", "cs2=APPID_ONEDRIVE", "|MCAS|SIEM_Agent|"]
  Fields = [
    """SIEM_Agent\|[^|]{1,2000}?\|({accesses}[^\|]{1,2000})\|""",
    """msg=(.+?):\s{0,100}({file_type}[^\s]{1,2000})\s{1,100}({file_parent}[^=]{1,2000})[\\\/]{1,2000}(|({file_name}.*?({file_ext}\.[^\\:\s.]{1,2000})?))\s{1,100}(?:$|\w+=)""",
    """msg=(.+?):\s{0,100}({src_file_type}[^\s]{1,2000})\s{1,100}({src_file_parent}[^=]{1,2000})[\\\/]{1,2000}({src_file_name}[^=]{0,2000}?({src_file_ext}\.[^\\:\s.=]{1,2000})?)\s{1,100}(to)\s{1,100}({file_type}[^\s]{1,2000})\s{1,100}({file_parent}[^=]{1,2000})[\\\/]{1,2000}(|({file_name}[^=]{0,2000}?({file_ext}\.[^\\:\s.=]{1,2000})?))\s{1,100}(?:$|\w+=)""",
    """\ssuser=({user}[^@]{1,2000})@([\.\w+]{1,2000}\.)?({email_domain}[^\.\s]{1,2000}\.(?:com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za|ch))\s{1,100}""",
    """\srt=({time}\d{1,100})""",
    """\sdestinationServiceName =({app}.+?)\s{1,100}\w+=""",
    """\srequestClientApplication=(|({user_agent}.+?))\s{1,100}\w+=""",
    """\sdvc=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """exabeam_host=({host}[^\s]{1,2000})"""
  ]


}
```