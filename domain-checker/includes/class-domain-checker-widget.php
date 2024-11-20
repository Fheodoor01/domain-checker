<?php
    class Domain_Checker_Widget extends WP_Widget {
        public function __construct() {
            parent::__construct(
                'domain_checker_widget',
                __('Domain Security Checker', 'domain-checker'),
                array('description' => __('Check domain security settings', 'domain-checker'))
            );
        }

        public function widget($args, $instance) {
            echo $args['before_widget'];
            
            if (!empty($instance['title'])) {
                echo $args['before_title'] . apply_filters('widget_title', $instance['title']) . $args['after_title'];
            }
            
            include DOMAIN_CHECKER_PLUGIN_DIR . 'templates/checker-form.php';
            
            echo $args['after_widget'];
        }

        public function form($instance) {
            $title = !empty($instance['title']) ? $instance['title'] : __('Domain Security Checker', 'domain-checker');
            ?>
            <p>
                <label for="<?php echo esc_attr($this->get_field_id('title')); ?>">
                    <?php esc_attr_e('Title:', 'domain-checker'); ?>
                </label>
                <input class="widefat" 
                       id="<?php echo esc_attr($this->get_field_id('title')); ?>" 
                       name="<?php echo esc_attr($this->get_field_name('title')); ?>" 
                       type="text" 
                       value="<?php echo esc_attr($title); ?>">
            </p>
            <?php
        }

        public function update($new_instance, $old_instance) {
            $instance = array();
            $instance['title'] = (!empty($new_instance['title'])) 
                ? strip_tags($new_instance['title'])
                : '';
            return $instance;
        }
    }
    ?>
