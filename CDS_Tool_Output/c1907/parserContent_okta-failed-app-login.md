#### Parser Content
```Java
{
Name = okta-failed-app-login
    Vendor = Okta
    Product = Okta MFA
    Lms = Direct
    DataType = "failed-app-login"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
    Conditions = [ """,Sign-""", """n Failed """]
    Fields = [
        """([^,]*,){2}({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
        """Sign-(i|I)n Failed.*?([^,]*,){3}({src_ip}[^,]+)""",
        """exabeam_host=({host}[^\s]+)""",
        """Verification failed for user:\s*(({user_email}[^"@]+@[^"@]+)|({user}[^"]+))"*,""",
        """([^,]*,){4}(({user_email}[^,@]+@[^,@]+)|({user}[^,]+))""",
        """Sign-(i|I)n Failed\s*-\s*({failure_reason}[^:",]+)""",
        """([^,]*,){11}\/app\/({app}[^\/]+)""",
    ]
  }
]


include "./parsers_wazuh.conf"
include "./parsers_shared.conf"
include "./parsers_windows.conf"
include "./parsers_pmp.conf"
include "./parsers_digitalguardian.conf"
include "./parsers_exchange.conf"
include "./parsers_duo.conf"
include "./parsers_unix.conf"
include "./parsers_microsoft_azure.conf"
include "./parsers_box.conf"
include "./parsers_okta.conf"
include "./parsers_juniper.conf"
include "./parsers_carbonblack.conf"
include "./parsers_paloalto.conf"
include "./parsers_mcafee.conf"
include "./parsers_citrix.conf"
include "./parsers_symantec.conf"
include "./parsers_microsoft.conf"
include "./parsers_fireeye.conf"
include "./parsers_imperva.conf"
include "./parsers_sophos.conf"
include "./parsers_checkpoint.conf"
include "./parsers_iis.conf"
include "./parsers_cisco.conf"
include "./parsers_fortinet.conf"
include "./parsers_vmware.conf"
include "./parsers_bluecoat.conf"
include "./parsers_trendmicro.conf"
include "./parsers_github.conf"
include "./parsers_rdirectory.conf"
include "./parsers_f5vpn.conf"
include "./parsers_stealthbits.conf"
include "./parsers_bro.conf"
include "./parsers_cyberarkvault.conf"
include "./parsers_zscaler.conf"
include "./parsers_proofpoint.conf"
include "./parsers_rsa.conf"
include "./parsers_websense.conf"
include "./parsers_crowdstrike.conf"
include "./parsers_skyfence.conf"
include "./parsers_svn.conf"
include "./parsers_ibm.conf"
include "./parsers_bromium.conf"
include "./parsers_dropbox.conf"
include "./parsers_salesforce.conf"
include "./parsers_windows_chinese.conf"
include "./parsers_bitglass.conf"
include "./parsers_rangeraudit.conf"
include "./parsers_damballafailsafe.conf"
include "./parsers_windows_japanese.conf"
include "./parsers_dtex.conf"
include "./parsers_oracle.conf"
include "./parsers_ovirt.conf"
include "./parsers_adaudit.conf"
include "./parsers_observeit.conf"
include "./parsers_kiteworks.conf"
include "./parsers_infowatch.conf"
include "./parsers_lanscopecat.conf"

AWSParserTemplates = {

s-aws-cloudtrail-activity-json = {
  Vendor = AWS CloudTrail
  Lms = Splunk
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Fields = [
    """"+eventTime"+\s*:\s*"+?(|({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)Z)"+\s*[,\]\}]""",
    """"+sourceIPAddress"+\s*:\s*"+?(({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({src_host}[^"].+?))"+\s*[,\]\}]""",
    """"+eventSource"+\s*:\s*"+?(|({host}[^"].+?))"+\s*[,\]\}]""",
    """"userIdentity".+?"+invokedBy"+\s*:\s*"+?(|({dest_host}[^"].+?))"+\s*[,\]\}]""",
    """({app}AwsApiCall)""",
    """"+eventName"+\s*:\s*"+?(|({activity_action}[^"].+?))"+\s*[,\]\}]""",
    """"userIdentity".+?"+arn"+\s*:\s*"+?(|arn:aws:sts::\d+:([^"]+\/)+({user}(?!\-\d+)[^\/]+?))"+\s*[,\]\}]""",
    """"+userName"+\s*:\s*"+?(|({user}[^"].+?))"+\s*[,\]\}]""",
    """"eventSource"\s*:\s*"(|({object}[^"]+))"""",
    """"sessionIssuer"\s*:\s*.*?"arn"\s*:\s*"(?:|({object}[^"]+))"""",
    """"bucketName"\s*:\s*"(|({object}[^"]+))"""",
    """"policyArn"\s*:\s*"(|({object}[^"]+))"""",
    """"roleName"\s*:\s*"(|({object}[^"]+))"""",
    """"userAgent"\s*:\s*"(|({user_agent}[^"]+))"""",
    """"+errorCode"+\s*:\s*"+?(|({activity_outcome}[^"].+?))"+\s*[,\]\}]""",
    """"+errorMessage"+\s*:\s*"+?(|({additional_info}[^"].+?))"+\s*[,\]\}]""",
    """"+accountId"+\s*:\s*"+?(|({resource}[^"].+?))"+\s*[,\]\}]""",
  ]
}
```