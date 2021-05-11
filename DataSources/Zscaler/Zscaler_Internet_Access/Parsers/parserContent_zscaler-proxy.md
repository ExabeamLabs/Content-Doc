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
      """\ssuser=(?![^\s]+@[^\s]+)({user}[^\s]+)""",
      """\ssuser=(?=[^\s]+@[^\s]+)({user_email}({user}[^\s@]+)@[^\s]+)""",
      """\ssuser=({user}[^\s@]+)@""",
      """\sduser=({browser}.+?)\s{1,100}(\(|\w+=)""",
      """\sact=({action}.+?)\s{1,100}\w+=""",
      """\snitroResponse_Code=({result_code}\d{1,100})""",
      """\snitroURL=({full_url}\S+)""",
      """\snitroURL_Category=({category}.+?)\s{1,100}(-|\w+=)""",
      """\snitroURL=(\w+:\/{2})?[^\/]+({uri_path}\/[^?\s]+)""",
      """\snitroURL=(\w+:\/+)?[^|\/:]+(:\d{1,100})?[^|?]+({uri_query}\?[^\s]+)""",
      """\snitroURL=(?:[^:?]+:\/+)?({web_domain}[^\/:\s]+)""",
      """\snitroURL=[^\s?=]*?({top_domain}(?!(?:\d{1,100}\.){3}\d{1,100})[^\.\s]+(?=(?:\.(?:com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za)(?::\d{1,100})?)+(?:\s\w+=|\/))[^\s:\/]+)""" ]
  }
```