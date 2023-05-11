<?php
/*======================================================================*/
/*
/*    WizQ API
/*
/*    Description : WizQRequestValidator for Yahoo Mobage
/*    Version : 2.0.8
/*    Copyright : (c) 2019 wizQ Interactive Limited All Rights Reserved.
/*
/*=======================================================================*/

require_once "OAuth.php";

class WizQRequestValidator
{
    public $key;
    public $secret;

    public function __construct($key, $secret)
    {
        $this->key = $key;
        $this->secret = $secret;
    }

    public function validateSignedRequest()
    {
        $request = OAuthRequest::from_request(null, null, array_merge($_GET, $_POST));
        $oauth_consumer_key = $request->get_parameter('oauth_consumer_key');
        $signature_method = $this->getSignatureMethod($oauth_consumer_key);
        if ($signature_method) {
            $signature_valid = $signature_method->check_signature($request, null, null, $request->get_parameter('oauth_signature'));
            return $signature_valid;
        }
        return false;
    }

    private function getIsSandBox()
    {
        $request = OAuthRequest::from_request(null, null, array_merge($_GET, $_POST));
        if ($request->get_parameter('oauth_consumer_key') == 'sb.mbga-platform.jp') {
            return true;
        }
        return false;
    }

    private function getSignatureMethod($oauth_consumer_key)
    {
        if ($oauth_consumer_key == 'sb.mbga-platform.jp') {
            return new YahooMobageSandboxSignatureMethod();
        } else if ($oauth_consumer_key == 'mbga-platform.jp') {
            return new YahooMobageSignatureMethod();
        } else {
            return null;
        }
    }

    public function getViewerID()
    {
        $viewerID = $_REQUEST['opensocial_viewer_id'];
        //Fix yahoo mobage bug , viewrid without 'sb.mbga.jp:' in sandbox mode
        if ($this->getIsSandBox()) {
            $viewerID = 'sb.mbga.jp:' . $viewerID;
        } else {
            $viewerID = 'mbga.jp:' . $viewerID;
        }
        return $viewerID;
    }
}

class YahooMobageSandboxSignatureMethod extends OAuthSignatureMethod_RSA_SHA1
{
    protected function fetch_public_cert(&$request)
    {
        return <<< EOD
-----BEGIN CERTIFICATE-----
MIICOTCCAaKgAwIBAgIJAK3cE459+jV9MA0GCSqGSIb3DQEBBQUAMB4xHDAaBgNV
BAMTE3NiLm1iZ2EtcGxhdGZvcm0uanAwHhcNMTcwNjMwMTI0ODI0WhcNMjcwNjMw
MTI0ODI0WjAeMRwwGgYDVQQDExNzYi5tYmdhLXBsYXRmb3JtLmpwMIGfMA0GCSqG
SIb3DQEBAQUAA4GNADCBiQKBgQDZ8xJKX1rPli72IF2L+tRV9Tk1c2kRixEEwzxR
T2bz37w/8XJQaMVxtFQMCYqquZUmHDss4JgF/prE4HGnX0j6x9MZUrt0k2VzDINm
Y+F61QJZCLqqy5MBxR9Dyu87DucPf7WsP3C1EMrfB8c29qVT7is+pMuYDowmsPql
eJ4pswIDAQABo38wfTAdBgNVHQ4EFgQUtNIqfC+B1PmcIhDmIA8+QxALZU4wTgYD
VR0jBEcwRYAUtNIqfC+B1PmcIhDmIA8+QxALZU6hIqQgMB4xHDAaBgNVBAMTE3Ni
Lm1iZ2EtcGxhdGZvcm0uanCCCQCt3BOOffo1fTAMBgNVHRMEBTADAQH/MA0GCSqG
SIb3DQEBBQUAA4GBAEhCO8EGF4gp//qWWp79AYwV++X1ZLPrmp72tNr8+Lzop+Dt
VD53X3ek+RCz+6GOBaSjrvgyBMotF87cHHu3G8XGR3b0RQbux2ECJh7MrQVpRJDk
D7Vm2uJi03zMNiUoYdElW8hLUPW6X/XRDW9KrlPHWWk/mabylQp0oi3PtKf3
-----END CERTIFICATE-----
EOD;
    }
    protected function fetch_private_cert(&$request)
    {
        return <<< EOD
-----BEGIN CERTIFICATE-----
MIICOTCCAaKgAwIBAgIJAK3cE459+jV9MA0GCSqGSIb3DQEBBQUAMB4xHDAaBgNV
BAMTE3NiLm1iZ2EtcGxhdGZvcm0uanAwHhcNMTcwNjMwMTI0ODI0WhcNMjcwNjMw
MTI0ODI0WjAeMRwwGgYDVQQDExNzYi5tYmdhLXBsYXRmb3JtLmpwMIGfMA0GCSqG
SIb3DQEBAQUAA4GNADCBiQKBgQDZ8xJKX1rPli72IF2L+tRV9Tk1c2kRixEEwzxR
T2bz37w/8XJQaMVxtFQMCYqquZUmHDss4JgF/prE4HGnX0j6x9MZUrt0k2VzDINm
Y+F61QJZCLqqy5MBxR9Dyu87DucPf7WsP3C1EMrfB8c29qVT7is+pMuYDowmsPql
eJ4pswIDAQABo38wfTAdBgNVHQ4EFgQUtNIqfC+B1PmcIhDmIA8+QxALZU4wTgYD
VR0jBEcwRYAUtNIqfC+B1PmcIhDmIA8+QxALZU6hIqQgMB4xHDAaBgNVBAMTE3Ni
Lm1iZ2EtcGxhdGZvcm0uanCCCQCt3BOOffo1fTAMBgNVHRMEBTADAQH/MA0GCSqG
SIb3DQEBBQUAA4GBAEhCO8EGF4gp//qWWp79AYwV++X1ZLPrmp72tNr8+Lzop+Dt
VD53X3ek+RCz+6GOBaSjrvgyBMotF87cHHu3G8XGR3b0RQbux2ECJh7MrQVpRJDk
D7Vm2uJi03zMNiUoYdElW8hLUPW6X/XRDW9KrlPHWWk/mabylQp0oi3PtKf3
-----END CERTIFICATE-----
EOD;
    }
}

class YahooMobageSignatureMethod extends OAuthSignatureMethod_RSA_SHA1
{
    protected function fetch_public_cert(&$request)
    {
        return <<< EOD
-----BEGIN CERTIFICATE-----
MIICMDCCAZmgAwIBAgIJAKgXukluiO9rMA0GCSqGSIb3DQEBBQUAMBsxGTAXBgNV
BAMTEG1iZ2EtcGxhdGZvcm0uanAwHhcNMTcwNjMwMTI1MTUxWhcNMjcwNjMwMTI1
MTUxWjAbMRkwFwYDVQQDExBtYmdhLXBsYXRmb3JtLmpwMIGfMA0GCSqGSIb3DQEB
AQUAA4GNADCBiQKBgQDJiPISeGA1qFk3iCX/71yYN7DiHQhkkcEokr0WiOoHXEMH
bq25kb2oMFrUthS3FldzlCJQl6qfYcI2Q48LFoLjaaORkhNuW5WzqvRQSezyRBNS
3Z8LBmlEkqBnwLMA3BQTtgNctMajEzRGxd/1eLg4bQwpjVwzokxBVjNDZNh3dwID
AQABo3wwejAdBgNVHQ4EFgQUDGmQcD11YTlCXrGvuwbeO2g9tR0wSwYDVR0jBEQw
QoAUDGmQcD11YTlCXrGvuwbeO2g9tR2hH6QdMBsxGTAXBgNVBAMTEG1iZ2EtcGxh
dGZvcm0uanCCCQCoF7pJbojvazAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBBQUA
A4GBAAwHUGNvsODKnKfiAs7MuPaQ4YYBjPv0ROwlfnh21i2OsYtmDupl2TIc9VTt
Ms/SVOrA3pQMaK9uzS2tAOTLwJ7/L5T5sNuMtlmseg4ywP+HupBLbxlUNqo5yfOc
jnP0cPWdpYJMGzNXHJWd34P5+G/xL+eBEdoxvfwNa37IcwlV
-----END CERTIFICATE-----
EOD;
    }
    protected function fetch_private_cert(&$request)
    {
        return <<< EOD
-----BEGIN CERTIFICATE-----
MIICMDCCAZmgAwIBAgIJAKgXukluiO9rMA0GCSqGSIb3DQEBBQUAMBsxGTAXBgNV
BAMTEG1iZ2EtcGxhdGZvcm0uanAwHhcNMTcwNjMwMTI1MTUxWhcNMjcwNjMwMTI1
MTUxWjAbMRkwFwYDVQQDExBtYmdhLXBsYXRmb3JtLmpwMIGfMA0GCSqGSIb3DQEB
AQUAA4GNADCBiQKBgQDJiPISeGA1qFk3iCX/71yYN7DiHQhkkcEokr0WiOoHXEMH
bq25kb2oMFrUthS3FldzlCJQl6qfYcI2Q48LFoLjaaORkhNuW5WzqvRQSezyRBNS
3Z8LBmlEkqBnwLMA3BQTtgNctMajEzRGxd/1eLg4bQwpjVwzokxBVjNDZNh3dwID
AQABo3wwejAdBgNVHQ4EFgQUDGmQcD11YTlCXrGvuwbeO2g9tR0wSwYDVR0jBEQw
QoAUDGmQcD11YTlCXrGvuwbeO2g9tR2hH6QdMBsxGTAXBgNVBAMTEG1iZ2EtcGxh
dGZvcm0uanCCCQCoF7pJbojvazAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBBQUA
A4GBAAwHUGNvsODKnKfiAs7MuPaQ4YYBjPv0ROwlfnh21i2OsYtmDupl2TIc9VTt
Ms/SVOrA3pQMaK9uzS2tAOTLwJ7/L5T5sNuMtlmseg4ywP+HupBLbxlUNqo5yfOc
jnP0cPWdpYJMGzNXHJWd34P5+G/xL+eBEdoxvfwNa37IcwlV
-----END CERTIFICATE-----
EOD;
    }
}
