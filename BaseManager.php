<?php
/**
 * Copyright (c) 2017. sn
 */

namespace sn\rbac;

use yii\base\Component;
use yii\base\InvalidConfigException;
use yii\base\InvalidParamException;
use yii\helpers\ArrayHelper;
use yii\rbac\Assignment;
use yii\rbac\ManagerInterface;

/**
 * BaseManager is a base class implementing [[ManagerInterface]] for RBAC management.
 *
 * For more details and usage information on DbManager, see the [guide article on security authorization](guide:security-authorization).
 *
 * @property Role[] $defaultRoleInstances Default roles. The array is indexed by the role names. This property
 * is read-only.
 *
 * @author Qiang Xue <qiang.xue@gmail.com>
 * @since 2.0
 */
abstract class BaseManager extends Component implements ManagerInterface
{
    /**
     * @var array a list of role names that are assigned to every user automatically without calling [[assign()]].
     */
    public $defaultRoles = [];


    /**
     * Returns the named auth item.
     * @param string $name the auth item name.
     * @return Item the auth item corresponding to the specified name. Null is returned if no such item.
     */
    abstract protected function getItem($name);

    /**
     * Returns the items of the specified type.
     * @param int $type the auth item type (either [[Item::TYPE_ROLE]] or [[Item::TYPE_PERMISSION]]
     * @return Item[] the auth items of the specified type.
     */
    abstract protected function getItems($type);

    /**
     * Adds an auth item to the RBAC system.
     * @param Item $item the item to add
     * @return bool whether the auth item is successfully added to the system
     * @throws \Exception if data validation or saving fails (such as the name of the role or permission is not unique)
     */
    abstract protected function addItem($item);

    /**
     * Adds a rule to the RBAC system.
     * @param Rule $rule the rule to add
     * @return bool whether the rule is successfully added to the system
     * @throws \Exception if data validation or saving fails (such as the name of the rule is not unique)
     */
    abstract protected function addRule($rule);

    /**
     * Removes an auth item from the RBAC system.
     * @param Item $item the item to remove
     * @return bool whether the role or permission is successfully removed
     * @throws \Exception if data validation or saving fails (such as the name of the role or permission is not unique)
     */
    abstract protected function removeItem($item);

    /**
     * Removes a rule from the RBAC system.
     * @param Rule $rule the rule to remove
     * @return bool whether the rule is successfully removed
     * @throws \Exception if data validation or saving fails (such as the name of the rule is not unique)
     */
    abstract protected function removeRule($rule);

    /**
     * Updates an auth item in the RBAC system.
     * @param string $name the name of the item being updated
     * @param Item $item the updated item
     * @return bool whether the auth item is successfully updated
     * @throws \Exception if data validation or saving fails (such as the name of the role or permission is not unique)
     */
    abstract protected function updateItem($name, $item);

    /**
     * Updates a rule to the RBAC system.
     * @param string $name the name of the rule being updated
     * @param Rule $rule the updated rule
     * @return bool whether the rule is successfully updated
     * @throws \Exception if data validation or saving fails (such as the name of the rule is not unique)
     */
    abstract protected function updateRule($name, $rule);

    /**
     * @inheritdoc
     */
    public function createRole($name)
    {
        $role = new Role();
        $role->name = $name;
        return $role;
    }

    /**
     * @inheritdoc
     */
    public function createCustomRole($name)
    {
        $role = new CustomRole();
        $role->name = $name;
        return $role;
    }

    /**
     * @inheritdoc
     */
    public function createPermission($name)
    {
        $permission = new Permission();
        $permission->name = $name;
        return $permission;
    }

    /**
     * @inheritdoc
     */
    public function add($object)
    {
        if ($object instanceof Item) {
            if ($object->ruleName && $this->getRule($object->ruleName) === null) {
                $rule = \Yii::createObject($object->ruleName);
                /**
                 * @var Rule $rule
                 */
                $rule->name = $object->ruleName;
                $this->addRule($rule);
            }
            return $this->addItem($object);
        } elseif ($object instanceof Rule) {
            return $this->addRule($object);
        }

        throw new InvalidParamException('Adding unsupported object type.');
    }

    /**
     * @inheritdoc
     */
    public function remove($object)
    {
        if ($object instanceof Item) {
            return $this->removeItem($object);
        } elseif ($object instanceof Rule) {
            return $this->removeRule($object);
        }

        throw new InvalidParamException('Removing unsupported object type.');
    }

    /**
     * @inheritdoc
     */
    public function update($name, $object)
    {
        if ($object instanceof Item) {
            if ($object->ruleName && $this->getRule($object->ruleName) === null) {
                $rule = \Yii::createObject($object->ruleName);
                $rule->name = $object->ruleName;
                /**
                 * @var Rule $rule
                 */
                $this->addRule($rule);
            }
            return $this->updateItem($name, $object);
        } elseif ($object instanceof Rule) {
            return $this->updateRule($name, $object);
        }

        throw new InvalidParamException('Updating unsupported object type.');
    }

    /**
     * @inheritdoc
     */

    /**
     * @inheritdoc
     */
    public function getPermission($name)
    {
        $item = $this->getItem($name);
        return $item instanceof Item && $item->type == Item::TYPE_PERMISSION ? $item : null;
    }

    /**
     * @inheritdoc
     */
    public function getRole($name)
    {
        $item = $this->getItem($name);
        return $item instanceof Item && ($item->type == Item::TYPE_ROLE || $item->type == Item::TYPE_CUSTOM_ROLE) ? $item : null;
    }

    /**
     * @param $name
     * @return null|\yii\rbac\Item
     */
    public function getCustomRole($name)
    {
        $item = $this->getItem($name);
        return $item instanceof Item && ($item->type == Item::TYPE_CUSTOM_ROLE) ? $item : null;
    }

    /**
     * @inheritdoc
     */
    public function getRoles()
    {
        return ArrayHelper::merge($this->getItems(Item::TYPE_ROLE), $this->getItems(Item::TYPE_CUSTOM_ROLE));
    }

    /**
     * @return array
     */
    public function getCustomRoles()
    {
        return $this->getItems(Item::TYPE_CUSTOM_ROLE);
    }

    /**
     * Returns defaultRoles as array of Role objects
     * @since 2.0.12
     * @return Role[] default roles. The array is indexed by the role names
     */
    public function getDefaultRoleInstances()
    {
        $result = [];
        foreach ($this->defaultRoles as $roleName) {
            $result[$roleName] = $this->createRole($roleName);
        }
        return $result;
    }

    /**
     * @inheritdoc
     */
    public function getPermissions()
    {
        return $this->getItems(Item::TYPE_PERMISSION);
    }

    /**
     * Executes the rule associated with the specified auth item.
     *
     * If the item does not specify a rule, this method will return true. Otherwise, it will
     * return the value of [[Rule::execute()]].
     *
     * @param string|int $user the user ID. This should be either an integer or a string representing
     * the unique identifier of a user. See [[\yii\web\User::id]].
     * @param Item $item the auth item that needs to execute its rule
     * @param array $params parameters passed to [[CheckAccessInterface::checkAccess()]] and will be passed to the rule
     * @return bool the return value of [[Rule::execute()]]. If the auth item does not specify a rule, true will be returned.
     * @throws InvalidConfigException if the auth item has an invalid rule.
     */
    protected function executeRule($user, $item, $params)
    {
        if ($item->ruleName === null) {
            return true;
        }
        $rule = $this->getRule($item->ruleName);
        if ($rule instanceof Rule) {
            return $rule->execute($user, $item, $params);
        }

        throw new InvalidConfigException("Rule not found: {$item->ruleName}");
    }

    /**
     * Checks whether array of $assignments is empty and [[defaultRoles]] property is empty as well
     *
     * @param Assignment[] $assignments array of user's assignments
     * @return bool whether array of $assignments is empty and [[defaultRoles]] property is empty as well
     * @since 2.0.11
     */
    protected function hasNoAssignments(array $assignments)
    {
        return empty($assignments);
    }
}
