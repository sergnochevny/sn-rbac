<?php
/**
 * Copyright (c) 2017. sn
 */

namespace sn\rbac;

/**
 * Class Item
 * @package sn\rbac
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
