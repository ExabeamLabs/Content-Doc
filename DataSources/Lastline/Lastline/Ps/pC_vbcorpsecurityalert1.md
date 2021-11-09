#### Parser Content
```Java
{
Name = vbcorp-security-alert-1
  Conditions = ["""Product=VBCorp""" , """グレーウェア"""]
}
vbcorp-security-alert = {
  Vendor = VBCorp
  Product = VBCorp
  Lms = Direct
  DataType = "alert"
  TimeFormat = "yyyy/MM/dd HH:mm:ss Z"
  Fields = [
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """日時:\s{0,100}({time}\d\d\d\d\/\d\d\/\d\d \d\d:\d\d:\d\d (\+|\-)\d\d:\d\d)""",
    """\shost=({host}[^\s]{1,2000})""",
    """(?:ユーザ名|ユーザ吁):?\s{0,100}(|({user}.+?))\s{0,100}IP""",
    """IPアドレス:\s{0,100}({src_ip}[^\s]{1,2000})\s{0,100}""",
    """MAC アドレス:\s{0,100}({src_mac}[^\s]{1,2000})\s{0,100}""",
    """({alert_type}(?:ウイルス\/不正プログラム|スパイウェア\/グレーウェア)):\s{0,100}({alert_name}[^\s]{1,2000})\s{0,100}""",
    """エンドポイント:\s{0,100}({src_host}[^\s]{1,2000})\s{0,100}""",
    """ドメイン:\s{0,100}({domain}.+?)\\?\s{0,100}(ファイル:|日時:)""",
    """ファイル:\s{0,100}(|({malware_url}.+?))\s{1,100}(日時:|\w+)\s{0,100}\d\d\d\d\/\d\d\/\d\d""",
    """結果:\s{0,100}(|({outcome}[^"]{1,2000}?))\s{0,100}"""",
  ]}
```