#### Parser Content
```Java
{
Name = s-bro-web-activity
  Vendor = Zeek
  Product = Zeek Network Security Monitor
  Lms = Splunk
  DataType = "web-activity"
  IsHVF = true
  TimeFormat = "epoch_sec"
  Conditions = [ "<custom-condition>" ]
  Fields = [
    """^[^\t]{0,2000}?({time}\d{1,100})\.\d{1,100}\t""",
    """^[^\t]{0,2000}?\t({host}[^\t]{1,2000})""",
    """^[^\t]{0,2000}?\t[^\t]{1,2000}\t({src_ip}[a-fA-F\d.:]{1,2000})""",
    """^[^\t]{0,2000}?\t([^\t]{1,2000}\t){2}({src_port}\d{1,100})""",
    """^[^\t]{0,2000}?\t([^\t]{1,2000}\t){3}({dest_ip}[a-fA-F\d.:]{1,2000})""",
    """^[^\t]{0,2000}?\t([^\t]{1,2000}\t){4}({dest_port}\d{1,100})""",
    """^[^\t]{0,2000}?\t([^\t]{1,2000}\t){6}({method}\w+)""",
    """^[^\t]{0,2000}?\t([^\t]{1,2000}\t){7}({web_domain}[^\t]{1,2000})""",
    """^[^\t]{0,2000}?\t([^\t]{1,2000}\t){8}({uri_path}[^\t\?]{1,2000})({uri_query}\?[^\t]{1,2000})?""",
    """^[^\t]{0,2000}?\t([^\t]{1,2000}\t){10}Mozilla\/.+\((({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin).+?({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident))""",
    """^[^\t]{0,2000}?\t([^\t]{1,2000}\t){13}({result_code}\w+)""",
    """^[^\t]{0,2000}?\t([^\t]{1,2000}\t){14}({result}(-|[^\t]{1,2000}))""",
    """^[^\t]{0,2000}?\t([^\t]{1,2000}\t){25}\s{0,100}({mime}[^\t]{1,2000}?)\s{0,100}""",
  ]


}
```