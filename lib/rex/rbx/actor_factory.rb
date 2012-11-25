# -*- coding: binary -*-

module Rex::Rbx

  ###
  #
  # This class provides a wrapper around Actor.new that can provide
  # additional features if a corresponding thread provider is set.
  #
  ###

  class ActorFactory
    include Rex::Rbx

    @@provider = nil

    def self.provider=(val)
      @@provider = val
    end

    def self.spawn(name, crit, *args, &block)
      if @@provider
        if block
          return @@provider.spawn(name, crit, *args){ |*args_copy| block.call(*args_copy) }
        else
          return @@provider.spawn(name, crit, *args)
        end
      else
        t = nil
        if block
          t = Actor.new(*args){ |*args_copy| block.call(*args_copy) }
        else
          t = Actor.new(*args)
        end
        t[:tm_name] = name
        t[:tm_crit] = crit
        t[:tm_time] = Time.now
        t[:tm_call] = caller
        return t
      end

    end
  end

end
