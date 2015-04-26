<?php
//namespace Habari;

class FacebookAuth extends Plugin
{
	private $service = 'Facebook';
	
	/**
	 * Outputs the "configure" button on the plugin page.
	 */
	public function filter_plugin_config( $actions, $plugin_id ) {
		if ( $plugin_id == $this->plugin_id() ) {
			return array( _t('Configure') );
		}
		return $actions;
	}
	
	/*
	 * Add config
	 */
	public function action_plugin_ui( $plugin_id, $action )
	{
		if ($plugin_id == $this->plugin_id() )
		{
			switch($action)
			{
				case _t('Configure'):
					$form = new FormUI( __CLASS__ );
					$form->append( 'text', 'redirect_uri', __CLASS__ . '__redirect_uri', _t( 'Redirect URI (relative to your domain)', __CLASS__ ));
					$form->append( 'text', 'client_id', __CLASS__ . '__client_id', _t( 'Client ID', __CLASS__ ));
					$form->append( 'text', 'client_secret', __CLASS__ . '__client_secret', _t( 'Client Secret', __CLASS__ ));
					$form->append( 'text', 'scope', __CLASS__ . '__scope', _t( 'Scopes (comma separated)', __CLASS__ ));
					$form->append( 'submit', 'save', _t( 'Save' ) );
					$form->out();
					break;
			}
		}
	}
	
	/*
	 * Add rewrite rule to catch the authentication result
	 */
	public function filter_rewrite_rules($rules)
    {
		$opts = Options::get_group( __CLASS__ );
		if(isset($opts['redirect_uri'])) {
			$rules[] = RewriteRule::create_url_rule('"' . $opts['redirect_uri'] . '"', 'PluginHandler', 'facebook_oauth_callback');
		}
		else {
			$rules[] = RewriteRule::create_url_rule('"facebook_oauth"', 'PluginHandler', 'facebook_oauth_callback');
		}
        return $rules;
    }
	
	/*
	 * Add Facebook to the list of social services providing the socialauth feature
	 */
	public function filter_socialauth_services($services = array())
	{
		$services[] = $this->service;
		return $services;
	}
	
	/*
	 * Provide auth link to the theme
	 * @param string $service The service / social network the link is requested for.
	 * @param array Accepts values for overriding the global options redirect_uri and scope and additional state, a value that will be roundtripped through the Google servers until returned with the redirect URI
	 */
	public function theme_socialauth_link($theme, $service, $paramarray = array())
	{
		// REFACTOR: Do something to avoid output of incomplete urls
		if($service == $this->service) {
			$opts = Options::get_group( __CLASS__ );
			
			$url = "https://www.facebook.com/dialog/oauth?";
			$url .= "client_id=" . $opts['client_id'];
			
			if(isset($paramarray['scope']) && !empty($paramarray['scope'])) {
				$url .= "&scope=" . $paramarray['scope'];
			}
			elseif(isset($opts['scope']) && !empty($opts['scope'])) {
				$url .= "&scope=" . $opts['scope'];
			}
			
			$url .= "&redirect_uri=" . URL::get('facebook_oauth_callback');

			if(isset($paramarray['state'])) {
				$url .= "&state=" . $paramarray['state'];
			}
			
			
			return $url;
		}
	}
	
	/*
	 * Handle the authentication result
	 */
	public function action_plugin_act_facebook_oauth_callback($handler)
	{
		$code = $_GET['code'];
		$state = $_GET['state'];
		$error = $_GET['error'];
		if(isset($error) && $error == 'access_denied') {
			return;
		}
		
		$opts = Options::get_group(__CLASS__);
		// Exchange code for token
		$request = new RemoteRequest("https://graph.facebook.com/v2.3/oauth/access_token?code=$code&client_id={$opts['client_id']}&client_secret={$opts['client_secret']}&redirect_uri=" . URL::get('facebook_oauth_callback'));
		$request->add_header('Accept: application/json');
		$request->execute();
		
		if ( ! $request->executed() ) {
			throw new XMLRPCException( 16 );
		}
		$json_response = $request->get_response_body();
		$jsondata = json_decode($json_response);
		$token = $jsondata->{'access_token'};
		
		// Offer the token to plugins that want to do something with the authenticated user
		Plugins::act('facebookauth_token', $token);
		
		// Get user info. Wrap in try-catch because we don't know if the userinfo is available
		try {
			$request = new RemoteRequest("https://graph.facebook.com/v2.3/me?access_token=$token");
			$request->execute();
			if ( ! $request->executed() ) {
				throw new XMLRPCException( 16 );
			}
			$json_response = $request->get_response_body();
			$jsondata = json_decode($json_response);
			
			// The following is important, because it's part of the "socialauth" feature API
			$userdata = array("id" => $jsondata->id);
			$userdata['name'] = $jsondata->name;
			$userdata['email'] = $jsondata->email;
			
			$request = new RemoteRequest("https://graph.facebook.com/v2.3/me?fields=picture&access_token=$token");
			$request->execute();
			if ( ! $request->executed() ) {
				throw new XMLRPCException( 16 );
			}
			$json_response = $request->get_response_body();
			$jsondata = json_decode($json_response);
			
			$userdata["portrait_url"] = $jsondata->picture->data->url;
			
			// Pass the identification data to plugins
			Plugins::act('socialauth_identified', $this->service, $userdata, $state);
		} catch(Exception $e) {
			// don't care if it fails, the only consequence is that action_social_auth will not be triggered, which is correct
		}
	}
}
?>
