/*!
 * mini-i18n.js JavaScript Library v1.0.0 
 * http://github.com/AndiSHFR/mini-i18n/
 * 
 * Copyright 2017 Andreas Schaefer
 * Licensed under the MIT license
 * 
 * @file 
 * JavaScript module to switch text elements in a web page on the fly.
 * The intended use is for switching display language on a web page.
 * 
 */

if ('undefined' === typeof jQuery) {
    throw new Error('mini-i18n\'s JavaScript requires jQuery.')
  }
  
  +function ($) {
    'use strict';
    var version = $.fn.jquery.split(' ')[0].split('.')
    if ((version[0] < 2 && version[1] < 9) || (version[0] == 1 && version[1] == 9 && version[2] < 1) || (version[0] > 3)) {
      throw new Error('mini-i18n\'s JavaScript requires jQuery version 1.9.1 or higher, but lower than version 4. You are using version ' + $.fn.jquery);
    }
  }(jQuery);
  
  
  +function(window, $, undefined) {
    'use strict';
  
    // PRIVATE
  
        // Help overcome console issues under IE when dev tools are not enabled but debug is set to true.
    var console = (window.console = window.console || {}),
  
        // Global options for this module
        options = {
          // True will output debug information on the developer console
          debug: false,
          // css style to be applied to the element if the language text for the key was not found
          notFound: 'lang-not-found',
          // If set this points to a RESTful api to GET the language text
          api: undefined,
          // User callback to be called _before_ a text is assigned to an element.
          // If the callback returns true the default behaviour will not be executed.
          onItem: undefined,
          // Data cache for already loaded/used languages
          data: []
        },
  
        /**
         * Output debug information to the developer console
         *
         * @param {object} args_
         * @return
         * @api private
         */
        debug = function(args_) {
          if(options.debug) {
            var args = [].slice.call(arguments);
            args.unshift('mini-i18n: ');
            console.log.apply(null, args);
          }
        },  
  
        /**
         * Get a value from an object by its path
         *
         * @param {object} obj
         * @param {string} path
         * @return {object}
         * @api private
         */
        deepValue = function(obj, path) {
          if('string' !== typeof path) return obj;
          path = path.replace(/\[(\w+)\]/g, '.$1');   // convert indexes to properties
          path = path.replace(/^\./, '').split('.');  // strip a leading dot and split at dots
          var i = 0, len = path.length;               
          while(obj && i < len) {
            obj = obj[path[i++]];
          }
          return obj;
        },
  
        /**
         * Loops thru all language elements and sets the current language text
         * 
         * @param {string} lang
         * @return
         * @api private
         */
        updateElements = function(lang) {
          debug('Updating elements with language: ' + lang);
          var data = options.data[lang],  // data containing language related text. 
              // Callback called for every item to allow custom handling
              // If the callback returns false the default handling take place
              cb = options.onItem || function() { return false; }
              ;
  
          // Select all elements and loop thru them
            $('[data-lang-ckey],[data-lang-tkey],[data-lang-pkey]').each(function () {
              debug('Updating:', this); 
            var $this = $(this),                 // jQuery object of the element            
                ckey = $this.attr('data-lang-ckey'), // Key for the content of the element
                tkey = $this.attr('data-lang-tkey'), // Key for title attribute of the element
                pkey = $this.attr('data-lang-pkey'), // Key for placeholder attribute of the element
                cval = deepValue(data, ckey),      // Value of the content
                tval = deepValue(data, tkey),      // Value of the title attribute
                pval = deepValue(data, pkey)       // Value of the placeholder attribute
                ;
  
            // Execute callback and if the result is false run the default action
            if(false === cb(this, lang, ckey, cval, tkey, tval, pkey, pval)) {
              // If there is a content key set the content and handle "not found" condition
              if(ckey) {
                $this
                .removeClass(options.notFound)
                .html(cval)
                .addClass( (cval ? undefined : options.notFound ) );
              }          
              // If there is a title key set the title attribute and handle "not found" condition
              if(tkey) {
                $this
                .removeClass(options.notFound)
                .attr('title', (tval || $this.attr('title')) )
                .addClass( (tval ? undefined : options.notFound ) );
              }
              // If there is a placeholder key set the placeholder attribute and handle "not found" condition
              if(pkey) {
                $this
                .removeClass(options.notFound)
                .attr('placeholder', (pval || $this.attr('placeholder')) )
                .addClass( (pval ? undefined : options.notFound ) );
              }
            }
          });
        },
        
        /**
         * Sets configuration values 
         * 
         * @param {object} options_
         * @return
         * @api private
         */
        configure = function(options_) {
          debug('configure with: ', options_);
          options = $.extend({}, options, options_);
        },
  
        /**
         * Switch language text on elements
         * 
         * @param {string} lang
         * @return
         * @api private
         */
        language = function(lang) {        
          debug('Switch to language: ', lang);
          if(!options.data[lang] && options.url) {
            var url = options.url + lang;
            debug('Requesting language data for "' + lang + '" from url "' + url + '"');          
            $.ajax({
              url: url,
             success: function(res) { 
               debug('Got response.', res);          
               options.data[lang] = res;
             },
             complete: function(res) { 
               if(!options.data[lang]) {
                 debug('Got no valid response. Language "' + lang + '" will not be available!');          
                 options.data[lang] = {}; // Create an empty object so further requests won't lead to ajax calls anymore.
               }
               updateElements(lang);
              }
            });
          } else {
            updateElements(lang);
          }
        }
        ;
  
    // PUBLIC
  
    /**
     * Public mini-i18n method.
     * Can be called in two ways.
     * Setting options    : p is an object with configuration settings.
     * Switching language : p is a string with the language name. i.e. 'en-US'
     * 
     * @param {object|string} p 
     * @return
     * @api public
     */
    $.fn.extend({
      miniI18n : function(p) {
        if('string' === typeof p) return language(p);
        if('object' === typeof p) return configure(p);
        throw new Error('Argument must be a string or an object with configuration values.');
      }
    });
  
  
    $(function() {
      // Auto initialize elements with attribute "data-lang-switch"
      $('[data-lang-switch]').on('click.mini-i18n', function(e) {
        e.preventDefault();
        var lang = $(this).attr('data-lang-switch');
        if(lang) $.fn.miniI18n(lang);
      });
    });
  
  }(window, jQuery);
  
