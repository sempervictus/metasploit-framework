#!/usr/bin/env ruby
# -*- coding: binary -*-

module ::Rex
  # Only define this namespace if we're in RBX
  # Then check with Rex.const_defined?(:Rbx)
  if Object.const_defined?(:RUBY_ENGINE) && RUBY_ENGINE == 'rbx'

    module Rbx
      # Rubinius specific components go here
      require 'rubinius/actor'

      class ActorKilled < ::Exception; end

      class Actor < Rubinius::Actor
        extend Forwardable
        def_delegators :@thread, :[], :[]=

        def alive?
          @alive
        end

        # Emulate thread.kill
        def kill( reason = ActorKilled )
          begin
            self.notify_exited(self,reason)
          rescue => e
            # If we are here, the actor is dead
            nil
          end
        end

        def thread
          @thread
        end

      end

    end
    # Additional requires go here
    require 'rex/rbx/actor_factory'
  end
end
