<?php
/*
 * (C) Copyright 2011 Nuxeo SA (http://nuxeo.com/) and contributors.
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the GNU Lesser General Public License
 * (LGPL) version 2.1 which accompanies this distribution, and is available at
 * http://www.gnu.org/licenses/lgpl.html
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * Contributors:
 *     Anthony OGIER
 *     David JONCOUR
 */

/**
 * PortalSSOAuthInterceptor class
 *
 * Class which intercepts NuxeoRequests in order to add SSO secret key
 *
 * @author     Anthony OGIER & David JONCOUR
 */
class PortalSSOAuthInterceptor {
    private $secretKey;
    private $userName;
    private $TOKEN_SEP = ":";

    public function PortalSSOAuthInterceptor($secretKey, $userName) {
        $this->secretKey = $secretKey;
        $this->userName = $userName;
    }

    public function intercept($nuxeoRequest) {
        // You need to multiply by 1000 to have a Java timestamp in PHP
        $ts = time()*1000;
        srand($ts);
        $random = rand();
        $clearToken = $ts.$this->TOKEN_SEP.$random.$this->TOKEN_SEP.$this->secretKey.$this->TOKEN_SEP.$this->userName;
        $base64HashedToken = base64_encode(md5($clearToken, true));

        $nuxeoRequest->addHeader('NX_TS', $ts);
        $nuxeoRequest->addHeader('NX_RD', $random);
        $nuxeoRequest->addHeader('NX_TOKEN', $base64HashedToken);
        $nuxeoRequest->addHeader('NX_USER', $this->userName);
    }
}

?>
