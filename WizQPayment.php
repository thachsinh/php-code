<?php
/*======================================================================*/
/*
/*    WizQ API
/*
/*    Description : WizQ API Payment
/*    Version : 2.0.8
/*    Copyright : (c) 2019 wizQ Interactive Limited All Rights Reserved.
/*
/*=======================================================================*/

require_once "WizQOAuth.php";

class WizQPayment
{
    public $key;
    public $secret;

    public function __construct($key, $secret)
    {
        $this->key = $key;
        $this->secret = $secret;
    }

    public function handleRequest()
    {
        $signValid = false;

        $req = WizQOAuthRequest::from_request(null, null, null);
        $consumer = new WizQOAuthConsumer($this->key, $this->secret, null);
        $token = new WizQOAuthToken($req->get_parameter('oauth_token'), $req->get_parameter('oauth_token_secret'));
        $signature = $req->get_parameter('oauth_signature');
        $signatureMethod = new WizQOAuthSignatureMethod_HMAC_SHA1();
        $signatureValid = $signatureMethod->check_signature($req, $consumer, $token, $signature);
        if ($signatureValid) {
            $cmd = $req->get_parameter('cmd');
            switch ($cmd) {
                case 'getItemInfo':
                    $this->getItemInfoHandler($req->get_parameter('sku_id'));
                    break;
                case 'updateInventory':
                    $this->updateInventoryHandler($req->get_parameter('order_id'),
                        $req->get_parameter('buyer_sns_id'),
                        $req->get_parameter('sku_id'),
                        $req->get_parameter('sku_quantity'),
                        $req->get_parameter('sku_unit_price'),
                        $req->get_parameter('item_id'),
                        $req->get_parameter('item_name'),
                        $req->get_parameter('item_quantity_per_order'),
                        $req->get_parameter('sns_paymenet_id')
                    );
                    break;
                default:
                    $this->requestError('Invalid Command');
                    break;
            }
        } else {
            $this->requestError('Invalid Signature');
        }
    }

    protected function getItemInfoHandler($skuID)
    {
        /*== Game Developer Implement get item info code here ==*/
        $getItemInfoSuccess = true;
        if ($getItemInfoSuccess) {
            //Case success
            $this->getItemInfoCompleted(210, 1, 'ItemName', 1);
        } else {
            //Case Failure , response with error details
            $this->requestError('Fail to connect database');
        }
    }

    protected function getItemInfoCompleted($skuUnitPrice, $itemID, $itemName, $itemQuantityPerOrder)
    {
        $response = array();
        $response['returnCode'] = true;
        $response['returnMessage'] = '';
        $response['skuUnitPrice'] = $skuUnitPrice;
        $response['itemID'] = $itemID;
        $response['itemName'] = $itemName;
        $response['itemQuantityPerOrder'] = $itemQuantityPerOrder;
        $this->responseRequest($response);
    }

    protected function updateInventoryHandler($orderID, $buyerSnsID, $skuID, $skuQuantity, $skuUnitPrice, $itemID, $itemName, $itemQuantityPerOrder, $snsPaymentID)
    {
        /*== Game Developer Implement update inventory code here ==*/
        $updateInventorySuccess = true;
        if ($updateInventorySuccess) {
            //Case success
            $this->updateInventoryCompleted();
        } else {
            //Case Failure , response with error details
            $this->requestError('Fail to connect database');
        }
    }

    protected function updateInventoryCompleted()
    {
        $response['returnCode'] = true;
        $response['returnMessage'] = '';
        $this->responseRequest($response);
    }

    protected function requestError($msg)
    {
        $response = array();
        $response['returnCode'] = false;
        $response['returnMessage'] = '[WizQPayment] Error : ' . $msg;
        $this->responseRequest($response);
    }

    protected function responseRequest($response)
    {
        $params = array();
        foreach ($response as $key => $value) {
            $params[$key] = $value;
        }
        ksort($params);
        $requestString = '';
        foreach ($params as $key => $value) {
            $requestString .= $key . '=' . urlencode($value);
        }
        $hash = hash_hmac('sha1', urlencode($requestString), $this->secret . '&', true);
        $signature = base64_encode($hash);
        $params['signature'] = $signature;
        echo json_encode($params);
    }
}
