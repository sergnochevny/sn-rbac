<?php
/**
 * Copyright (c) 2017. AIT
 */

namespace ait\rbac;

use yii\base\BaseObject;

/**
 * Class Item
 * @package ait\rbac
 */
class Item extends \yii\rbac\Item
{
    /**
     *
     */
    const TYPE_CUSTOM_ROLE = 3;

    /**
     * @var bool
     */
    public $allow = true;
}
