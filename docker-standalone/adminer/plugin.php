<?php
/** Adminer customization allowing usage of plugins
 * @link https://www.adminer.org/plugins/#use
 * @author Jakub Vrana, https://www.vrana.cz/
 * @license https://www.apache.org/licenses/LICENSE-2.0 Apache License, Version 2.0
 * @license https://www.gnu.org/licenses/gpl-2.0.html GNU General Public License, version 2 (one or other)
 */

// Only define AdminerPlugin if Adminer class exists
if (!class_exists('Adminer')) {
    return;
}

class AdminerPlugin extends Adminer {
    /** @access protected */
    var $plugins;
    
    function _construct($plugins) {
        $this->plugins = $plugins;
        // Compatibility with old constructor style
        if (func_num_args() > 0) {
            $this->plugins = func_get_args();
        }
    }
    
    function __construct($plugins) {
        $this->plugins = $plugins;
    }
    
    function _callParent($function, $args) {
        return call_user_func_array(array('Adminer', $function), $args);
    }
    
    function _appendPlugin($function, $args) {
        $return = $this->_callParent($function, $args);
        foreach ($this->plugins as $plugin) {
            if (method_exists($plugin, $function)) {
                $value = call_user_func_array(array($plugin, $function), $args);
                if ($value !== null) {
                    $return = $value;
                }
            }
        }
        return $return;
    }
    
    function _applyPlugin($function, $args) {
        foreach ($this->plugins as $plugin) {
            if (method_exists($plugin, $function)) {
                switch (count($args)) { // PHP doesn't support $this->plugin->$function(...$args)
                    case 0: $return = $plugin->$function(); break;
                    case 1: $return = $plugin->$function($args[0]); break;
                    case 2: $return = $plugin->$function($args[0], $args[1]); break;
                    case 3: $return = $plugin->$function($args[0], $args[1], $args[2]); break;
                    case 4: $return = $plugin->$function($args[0], $args[1], $args[2], $args[3]); break;
                    case 5: $return = $plugin->$function($args[0], $args[1], $args[2], $args[3], $args[4]); break;
                    case 6: $return = $plugin->$function($args[0], $args[1], $args[2], $args[3], $args[4], $args[5]); break;
                    default: 
                        $return = call_user_func_array(array($plugin, $function), $args);
                }
                if ($return !== null) {
                    return $return;
                }
            }
        }
        return $this->_callParent($function, $args);
    }
    
    // Plugin hooks
    function name() {
        return $this->_appendPlugin(__FUNCTION__, func_get_args());
    }
    
    function credentials() {
        return $this->_applyPlugin(__FUNCTION__, func_get_args());
    }
    
    function connectSsl() {
        return $this->_applyPlugin(__FUNCTION__, func_get_args());
    }
    
    function permanentLogin($create = false) {
        return $this->_applyPlugin(__FUNCTION__, func_get_args());
    }
    
    function bruteForceKey() {
        return $this->_applyPlugin(__FUNCTION__, func_get_args());
    }
    
    function serverName($server) {
        return $this->_applyPlugin(__FUNCTION__, func_get_args());
    }
    
    function database() {
        return $this->_applyPlugin(__FUNCTION__, func_get_args());
    }
    
    function schemas() {
        return $this->_applyPlugin(__FUNCTION__, func_get_args());
    }
    
    function databases($flush = true) {
        return $this->_applyPlugin(__FUNCTION__, func_get_args());
    }
    
    function queryTimeout() {
        return $this->_applyPlugin(__FUNCTION__, func_get_args());
    }
    
    function headers() {
        return $this->_applyPlugin(__FUNCTION__, func_get_args());
    }
    
    function csp() {
        return $this->_applyPlugin(__FUNCTION__, func_get_args());
    }
    
    function head() {
        return $this->_appendPlugin(__FUNCTION__, func_get_args());
    }
    
    function css() {
        return $this->_appendPlugin(__FUNCTION__, func_get_args());
    }
    
    function loginForm() {
        return $this->_applyPlugin(__FUNCTION__, func_get_args());
    }
    
    function loginFormField($name, $heading, $value) {
        return $this->_applyPlugin(__FUNCTION__, func_get_args());
    }
    
    function login($login, $password) {
        return $this->_applyPlugin(__FUNCTION__, func_get_args());
    }
    
    function tableName($tableStatus) {
        return $this->_applyPlugin(__FUNCTION__, func_get_args());
    }
    
    function fieldName($field, $order = 0) {
        return $this->_applyPlugin(__FUNCTION__, func_get_args());
    }
    
    function selectLinks($tableStatus, $set = "") {
        return $this->_applyPlugin(__FUNCTION__, func_get_args());
    }
    
    function foreignKeys($table) {
        return $this->_applyPlugin(__FUNCTION__, func_get_args());
    }
    
    function backwardKeys($table, $tableName) {
        return $this->_applyPlugin(__FUNCTION__, func_get_args());
    }
    
    function backwardKeysPrint($backwardKeys, $row) {
        return $this->_applyPlugin(__FUNCTION__, func_get_args());
    }
    
    function selectQuery($query, $start, $failed = false) {
        return $this->_applyPlugin(__FUNCTION__, func_get_args());
    }
    
    function sqlCommandQuery($query) {
        return $this->_applyPlugin(__FUNCTION__, func_get_args());
    }
    
    function rowDescription($table) {
        return $this->_applyPlugin(__FUNCTION__, func_get_args());
    }
    
    function rowDescriptions($rows, $foreignKeys) {
        return $this->_applyPlugin(__FUNCTION__, func_get_args());
    }
    
    function selectLink($val, $field) {
        return $this->_applyPlugin(__FUNCTION__, func_get_args());
    }
    
    function selectVal($val, $link, $field, $original) {
        return $this->_applyPlugin(__FUNCTION__, func_get_args());
    }
    
    function editVal($val, $field) {
        return $this->_applyPlugin(__FUNCTION__, func_get_args());
    }
    
    function tableStructurePrint($fields) {
        return $this->_applyPlugin(__FUNCTION__, func_get_args());
    }
    
    function tableIndexesPrint($indexes) {
        return $this->_applyPlugin(__FUNCTION__, func_get_args());
    }
    
    function selectColumnsPrint($select, $columns) {
        return $this->_applyPlugin(__FUNCTION__, func_get_args());
    }
    
    function selectSearchPrint($where, $columns, $indexes) {
        return $this->_applyPlugin(__FUNCTION__, func_get_args());
    }
    
    function selectOrderPrint($order, $columns, $indexes) {
        return $this->_applyPlugin(__FUNCTION__, func_get_args());
    }
    
    function selectLimitPrint($limit) {
        return $this->_applyPlugin(__FUNCTION__, func_get_args());
    }
    
    function selectLengthPrint($text_length) {
        return $this->_applyPlugin(__FUNCTION__, func_get_args());
    }
    
    function selectActionPrint($indexes) {
        return $this->_applyPlugin(__FUNCTION__, func_get_args());
    }
    
    function selectCommandPrint() {
        return $this->_applyPlugin(__FUNCTION__, func_get_args());
    }
    
    function selectImportPrint() {
        return $this->_applyPlugin(__FUNCTION__, func_get_args());
    }
    
    function selectEmailPrint($emailFields, $columns) {
        return $this->_applyPlugin(__FUNCTION__, func_get_args());
    }
    
    function selectColumnsProcess($columns, $indexes) {
        return $this->_applyPlugin(__FUNCTION__, func_get_args());
    }
    
    function selectSearchProcess($fields, $indexes) {
        return $this->_applyPlugin(__FUNCTION__, func_get_args());
    }
    
    function selectOrderProcess($fields, $indexes) {
        return $this->_applyPlugin(__FUNCTION__, func_get_args());
    }
    
    function selectLimitProcess() {
        return $this->_applyPlugin(__FUNCTION__, func_get_args());
    }
    
    function selectLengthProcess() {
        return $this->_applyPlugin(__FUNCTION__, func_get_args());
    }
    
    function selectEmailProcess($where, $foreignKeys) {
        return $this->_applyPlugin(__FUNCTION__, func_get_args());
    }
    
    function selectQueryBuild($select, $where, $group, $order, $limit, $page) {
        return $this->_applyPlugin(__FUNCTION__, func_get_args());
    }
    
    function messageQuery($query, $time, $failed = false) {
        return $this->_applyPlugin(__FUNCTION__, func_get_args());
    }
    
    function editInput($table, $field, $attrs, $value) {
        return $this->_applyPlugin(__FUNCTION__, func_get_args());
    }
    
    function editHint($table, $field, $value) {
        return $this->_applyPlugin(__FUNCTION__, func_get_args());
    }
    
    function processInput($field, $value, $function = "") {
        return $this->_applyPlugin(__FUNCTION__, func_get_args());
    }
    
    function dumpDatabase($db) {
        return $this->_applyPlugin(__FUNCTION__, func_get_args());
    }
    
    function dumpTable($table, $style, $is_view = 0) {
        return $this->_applyPlugin(__FUNCTION__, func_get_args());
    }
    
    function dumpData($table, $style, $query) {
        return $this->_applyPlugin(__FUNCTION__, func_get_args());
    }
    
    function dumpFilename($identifier) {
        return $this->_applyPlugin(__FUNCTION__, func_get_args());
    }
    
    function dumpHeaders($identifier, $multi_table = false) {
        return $this->_applyPlugin(__FUNCTION__, func_get_args());
    }
    
    function dumpHeadersCommand() {
        return $this->_applyPlugin(__FUNCTION__, func_get_args());
    }
    
    function dumpOutput() {
        return $this->_applyPlugin(__FUNCTION__, func_get_args());
    }
    
    function dumpFormat() {
        return $this->_applyPlugin(__FUNCTION__, func_get_args());
    }
    
    function homepage() {
        return $this->_applyPlugin(__FUNCTION__, func_get_args());
    }
    
    function navigation($missing) {
        return $this->_applyPlugin(__FUNCTION__, func_get_args());
    }
    
    function databasesPrint($missing) {
        return $this->_applyPlugin(__FUNCTION__, func_get_args());
    }
    
    function tablesPrint($tables) {
        return $this->_applyPlugin(__FUNCTION__, func_get_args());
    }
}