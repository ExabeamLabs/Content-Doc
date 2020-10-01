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
    """^[^\t]*?({time}\d+)\.\d+\t""",
    """^[^\t]*?\t({host}[^\t]+)""",
    """^[^\t]*?\t[^\t]+\t({src_ip}[a-fA-F\d.:]+)""",
    """^[^\t]*?\t([^\t]+\t){2}({src_port}\d+)""",
    """^[^\t]*?\t([^\t]+\t){3}({dest_ip}[a-fA-F\d.:]+)""",
    """^[^\t]*?\t([^\t]+\t){4}({dest_port}\d+)""",
    """^[^\t]*?\t([^\t]+\t){6}({method}\w+)""",
    """^[^\t]*?\t([^\t]+\t){7}({web_domain}[^\t]+)""",
    """^[^\t]*?\t([^\t]+\t){7}[^\t]*?({top_domain}[^\t.]+(?i)(\.(com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za))+)""",
    """^[^\t]*?\t([^\t]+\t){8}({uri_path}[^\t\?]+)({uri_query}\?[^\t]+)?""",

    """^[^\t]*?\t([^\t]+\t){10}Mozilla\/.+\((({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin).+?({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident))""",
    """^[^\t]*?\t([^\t]+\t){13}({result_code}\w+)""",
    """^[^\t]*?\t([^\t]+\t){14}({result}(-|[^\t]+))""",
    """^[^\t]*?\t([^\t]+\t){25}\s*({mime}[^\t]+?)\s*""",
  ]
}
```