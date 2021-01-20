#### Parser Content
```Java
{
Name = bro-httpeth0
  Vendor = Bro
  Product = Bro
  Lms = Direct
  DataType = "web-activity"
  TimeFormat = "epoch_sec"
  Conditions = [ "/http_eth0.log" ]
  Fields = [
    """exabeam_host=({host}[\w.\-]+)""",
    """({time}\d{10})\.\d{6}\t({conn_id}[^\t]+)\t(?:-|(({src_ip}(\d{1,3}\.){3}\d{1,3}|([A-Fa-f0-9%.]*:[A-Fa-f0-9%.:]+(th0)?))|[^\t]+))\t(?:-|(({src_port}\d+?)|[^\t]+))\t(?:-|(({dest_ip}(\d{1,3}\.){3}\d{1,3}|([A-Fa-f0-9%.]*:[A-Fa-f0-9%.:]+(th0)?))|[^\t]+))\t(?:-|(({dest_port}\d+?)|[^\t]+))\t(?:-|([^\t]+))\t(?:-|({method}[^\t]+))\t(?:-|([^\t]+))\t([^\t]+)\t(?:-|({referrer}[^\t]+))\t(?:-|([^\t]+))\t(?:-|({user_agent}[^\t]+))\t(?:-|([^\t]+))\t(?:-|([^\t]+))\t(?:-|({result_code}[^\t]+))\t(?:-|({status_msg}[^\t]+))\t(?:-|([^\t]+))\t(?:-|([^\t]+))\t(?:-|(\(empty\))|({tags}[^\t]+))\t(?:-|({user}[^\t]+))\t(?:-|([^\t]+))\t(?:-|({proxied}[^\t]+))\t(?:-|([^\t]+))\t(?:-|({orig_filenames}[^\t]+))\t(?:-|([^\t]+))\t(?:-|([^\t]+))\t(?:-|([^\t]+))\t(?:-|({mime}[^\t]+?))\s*$""",
    """({time}\d{10})\.\d{6}\t({conn_id}[^\t]+)\t(?:-|(({src_ip}(\d{1,3}\.){3}\d{1,3}|([A-Fa-f0-9%.]*:[A-Fa-f0-9%.:]+(th0)?))|[^\t]+))\t(?:-|(({src_port}\d+?)|[^\t]+))\t(?:-|(({dest_ip}(\d{1,3}\.){3}\d{1,3}|([A-Fa-f0-9%.]*:[A-Fa-f0-9%.:]+(th0)?))|[^\t]+))\t(?:-|(({dest_port}\d+?)|[^\t]+))\t(?:-|([^\t]+))\t(?:-|({method}[^\t]+))\t(?:-|([^\t]+))\t([^\t]+)\t(?:-|({referrer}[^\t]+))\t(?:-|({user_agent}[^\t]+))\t(?:-|([^\t]+))\t(?:-|([^\t]+))\t(?:-|({result_code}[^\t]+))\t(?:-|({status_msg}[^\t]+))\t(?:-|([^\t]+))\t(?:-|([^\t]+))\t(?:-|({orig_filenames}[^\t]+))\t(?:-|(\(empty\))|({tags}[^\t]+))\t(?:-|({user}[^\t]+))\t(?:-|([^\t]+))\t(?:-|({proxied}[^\t]+))\t(?:-|([^\t]+))\t(?:-|([^\t]+))\t(?:-|([^\t]+))\t(?:-|({mime}[^\t]+?))\s*$""",
    """\d{10}\.\d{6}\t([^\t]+\t){7}(?:-|(?!(\d{1,3}\.){3}\d{1,3})({web_domain}.+?))\s*\t([^\t]+\t){16}(?:-|({mime}[^\t]+))\t""",
    """\d{10}\.\d{6}\t([^\t]+\t){7}[^\t]*?({top_domain}[^\t.]+(?:\.(?:com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za))+)""",
    """\d{10}\.\d{6}\t([^\t]+\t){8}(?:-|({uri_path}[^\t\?]+)(\?({uri_query}[^\t]+))?)""",
    """\d{10}\.\d{6}\t([^\t]+\t){11}[^\t]*?({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident)""",
    """\d{10}\.\d{6}\t([^\t]+\t){11}[^\t]*?({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin)""",
    """({protocol}http)"""
  ]
}
```