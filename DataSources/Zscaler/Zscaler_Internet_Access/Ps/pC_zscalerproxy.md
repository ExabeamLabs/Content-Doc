#### Parser Content
```Java
{
Name = zscaler-proxy
    Vendor = Zscaler
    Product = Zscaler Internet Access
    Lms = Direct
    DataType = "web-activity"
    IsHVF = true
    TimeFormat = "epoch"
    Conditions = [ """|McAfee|ESM|""","""ZSCALER"""]
    Fields = [
      """\srt=({time}\d{1,100})""",
      """\sdeviceTranslatedAddress=({host}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
      """\ssrc=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
      """\sdst=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""
      """\ssuser=(?![^\s]{1,2000}@[^\s]{1,2000})({user}[^\s]{1,2000})""",
      """\ssuser=(?=[^\s]{1,2000}@[^\s]{1,2000})({user_email}({user}[^\s@]{1,2000})@[^\s]{1,2000})""",
      """\ssuser=({user}[^\s@]{1,2000})@""",
      """\sduser=({browser}.+?)\s{1,100}(\(|\w+=)""",
      """\sact=({action}.+?)\s{1,100}\w+=""",
      """\snitroResponse_Code=({result_code}\d{1,100})""",
      """\snitroURL=({full_url}\S+)""",
      """\snitroURL_Category=({category}.+?)\s{1,100}(-|\w+=)""",
      """\snitroURL=(\w+:\/{2})?[^\/]{1,2000}({uri_path}\/[^?\s]{1,2000})""",
      """\snitroURL=(\w+:\/+)?[^|\/:]{1,2000}(:\d{1,100})?[^|?]{1,2000}({uri_query}\?[^\s]{1,2000})""",
      """\snitroURL=(?:[^:?]{1,2000}:\/+)?({web_domain}[^\/:\s]{1,2000})""",
      """\snitroURL=[^\s?=]{0,2000}?({top_domain}(?!(?:\d{1,100}\.){3}\d{1,100})[^\.\s]{1,2000}(?=(?:\.(?:com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za)(?::\d{1,100})?)+(?:\s\w+=|\/))[^\s:\/]{1,2000})""" ]
  

}
```